/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        TCP library.
 *
 * Author:      Riccardo Coccioli, <volans-@users.noreply.github.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details:
 *              <http://www.gnu.org/licenses/>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License or (at your option) any later version.
 *
 * Copyright (C) 2016 Riccardo Coccioli, <volans-@users.noreply.github.com>
 */

#include <sys/types.h>          /* socket(), uint8_t, uint16_t, uint32_t */
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>          /* inet_pton(), inet_ntop() */
#include <bits/ioctls.h>        /* ioctl related defines */
#include <linux/if_ether.h>     /* ethernet type codes (ETH_P_IP, ETH_P_ARP) */
#include <net/ethernet.h>
#include <net/if.h>             /* struct ifreq */
#include <netinet/in.h>         /* IPPROTO_TCP, INET_ADDRSTRLEN */
#include <netpacket/packet.h>   /* struct sockaddr_ll */

#include <errno.h>              /* errno, perror() */
#include <netdb.h>              /* struct addrinfo */
#include <stdarg.h>             /* va_* type and functions */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>             /* strcpy, memset(), memcpy() */
#include <time.h>
#include <unistd.h>             /* close() */

#include "common.h"

#define TCP_ECE (1 << 6)
#define TCP_CWR (1 << 7)

/*
 * Struct to handle all the open file descriptors
 */
static struct sockets_descriptors {
    int raw_sd;  /* The raw socket descriptor */
    int stream_sd;  /* The stream socket descriptor */
} rsc_sockets = {0};

/*
 * Pseudo TCP header struct to calculate the TCP checkusm
 */
struct pseudo_tcp_header {
    uint32_t ip_src_addr;  /* IP header source address */
    uint32_t ip_dst_addr;  /* IP header destination address */
    uint8_t ip_zero;  /* IP header zero field */
    uint8_t ip_proto;  /* IP header protocol */
    uint16_t ip_payload_len;  /* IP payload length (TCP header + data) */
    uint16_t tcp_sport;  /* TCP header source port */
    uint16_t tcp_dport;  /* TCP header destination port */
    uint32_t tcp_seq;  /* TCP header sequence number */
    uint32_t tcp_ack;  /* TCP header acknowledgement number */
    uint8_t tcp_offset_reserved;  /* TCP header offset + reserved fields */
    uint8_t tcp_flags;  /* TCP header flags */
    uint16_t tcp_win;  /* TCP header window size */
    uint16_t tcp_sum;  /* TCP header checkusm (0 in pseudo header) */
    uint16_t tcp_urp;  /* TCP header urgent pointer */
};

/*
 * Print a TCP packet with a format inspired by tcpdump
 *
 *      |--- SRC ---|   |--- DST ---| |--------- TCP additional info --------|
 *      (MAC) IP:PORT > IP:PORT (MAC) Flags [TCP_FLAGS], seq 12345, ack 12345
 *
 * where TCP_FLAGS use the same syntax of tcpdump:
 *      FIN: F, SYN: S, RST: R, PUSH: P, ACK: ., URG: U, ECE: E, CWR: W
 */
static void
print_tcp_packet(verbosity_level_type level, packet_type *pck, FILE *output)
{
    int i;

    if (check_verbosity(level, RSC_NOOP_VERBOSITY) == 0)
        return;

    fprintf(output, "(");
    /* Source MAC address */
    for (i=0; i<5; i++) {
        fprintf(output, "%02x:", pck->src_mac[i]);
    }
    fprintf(output, "%02x) ", pck->src_mac[5]);

    /* Source IP:Port -> Destination IP:Port */
    fprintf(output, "%s:%u > ", inet_ntoa(pck->src_ip), pck->src_port);
    fprintf(output, "%s:%u (", inet_ntoa(pck->dst_ip), pck->dst_port);

    /* Destination MAC Address */
    for (i=0; i<5; i++) {
        fprintf(output, "%02x:", pck->dst_mac[i]);
    }
    fprintf(output, "%02x) ", pck->dst_mac[5]);

    /* TCP Flags, same format of tcpdump */
    fprintf(output, "Flags [");
    if (pck->tcphdr.th_flags == 0) {
        fprintf(output, "none");
    } else {
        if (pck->tcphdr.th_flags & TH_FIN) fprintf(output, "F");
        if (pck->tcphdr.th_flags & TH_SYN) fprintf(output, "S");
        if (pck->tcphdr.th_flags & TH_RST) fprintf(output, "R");
        if (pck->tcphdr.th_flags & TH_PUSH) fprintf(output, "P");
        if (pck->tcphdr.th_flags & TH_ACK) fprintf(output, ".");
        if (pck->tcphdr.th_flags & TH_URG) fprintf(output, "U");
        if (pck->tcphdr.th_flags & TCP_ECE) fprintf(output, "E");
        if (pck->tcphdr.th_flags & TCP_CWR) fprintf(output, "W");
    }

    /* Additional TCP info */
    fprintf(output, "], seq %u, ack %u\n", ntohl(pck->tcphdr.th_seq),
        ntohl(pck->tcphdr.th_ack));
}

/*
 * Print an ARP request/reply with a format inspired by tcpdump
 *
 *      (MAC) IP ARP request who has IP (MAC)
 *      (MAC) IP ARP reply to IP (MAC)
 */
static void
print_arp_packet(verbosity_level_type level, packet_type *pck, FILE *output)
{
    int i;

    if (check_verbosity(level, RSC_NOOP_VERBOSITY) == 0)
        return;

    fprintf(output, "(");

    /* Source MAC address */
    for (i=0; i<5; i++) {
        fprintf(output, "%02x:", pck->src_mac[i]);
    }
    fprintf(output, "%02x) ", pck->src_mac[5]);

    /* Source IP */
    fprintf(output, "%s ARP ", inet_ntoa(pck->src_ip));
    if (ntohs(pck->arphdr.ar_op) == ARPOP_REQUEST) {
        fprintf(output, "request who has ");
    } else if (ntohs(pck->arphdr.ar_op) == ARPOP_REPLY) {
        fprintf(output, "reply to ");
    }

    /* Destination IP */
    fprintf(output, "%s (", inet_ntoa(pck->dst_ip));

    /* Destination MAC Address */
    for (i=0; i<5; i++) {
        fprintf(output, "%02x:", pck->dst_mac[i]);
    }
    fprintf(output, "%02x) \n", pck->dst_mac[5]);
}

/*
 * Print any packet to stderr
 */
static void
print_packet_stderr(packet_type *pck)
{
    if (ntohs(pck->iphdr.ip_p) > 0)
        print_tcp_packet(RSC_NO_VERBOSITY, pck, stderr);
    else if (ntohs(pck->arphdr.ar_op) > 0)
        print_arp_packet(RSC_NO_VERBOSITY, pck, stderr);
}

/*
 * Set the source address variables in the packet from the network interface.
 */
static void
set_src_addr(int sd, char iface[], packet_type *pck)
{
    struct ifreq ifr = {{{0}}};
    struct sockaddr_ll *addr = {0};

    /* Get information from iface name */
    ifr.ifr_addr.sa_family = AF_INET; /* IPv4 address */
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);

    /* Get MAC address. */
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
        exit_on_perror("ioctl() failed to get source MAC address", pck);

    memcpy(pck->src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    /* Get IPv4 address */
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
        exit_on_perror("ioctl() failed to get source IPv4 address", pck);

    memcpy(&pck->src_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr,
            sizeof(struct in_addr));

    /* Set the st_addr needed by sendto(), recvfrom() */
    addr = (struct sockaddr_ll *) &(pck->st_addr);

    /* Get interface index, needed by sendto(), recvfrom() */
    if ((addr->sll_ifindex = if_nametoindex(iface)) == 0)
        exit_on_perror("if_nametoindex() failed to obtain interface index",
            pck);

    /* Set the other st_addr variables */
    addr->sll_family = PF_PACKET;
    addr->sll_halen = 6;
    memcpy(addr->sll_addr, pck->src_mac, 6 * sizeof(uint8_t));
}

/*
 * Resolve the destination address
 */
static void
resolve_dst(char dst[], struct sockaddr_in *addr)
{
    int status;
    struct addrinfo hints = {0};
    struct addrinfo *res;

    /* Fill out hints for getaddrinfo(). */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_CANONNAME;

    /* Resolve destination using getaddrinfo(). */
    if ((status = getaddrinfo(dst, NULL, &hints, &res)) != 0) {
        exit_on_error(NULL,
            "getaddrinfo() failed to resolve destination %s: %s\n",
            dst, gai_strerror(status));
    }

    memcpy(addr, (struct sockaddr_in *) res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
}

/*
 * Set the destination IPv4.
 */
static void
set_dst_ip(char dst[], packet_type *pck)
{
    struct sockaddr_in addr = {0};

    resolve_dst(dst, &addr);

    /* Set destination IPv4 */
    memcpy(&pck->dst_ip, (struct in_addr *) &(addr.sin_addr),
        sizeof(addr.sin_addr));
}

/*
 * Compute internet checksum
 *
 * See: https://tools.ietf.org/html/rfc1071
 */
static uint16_t
checksum(uint16_t *addr, int count)
{
    uint32_t sum = 0;

    while (count > 1)  {
        sum += *(addr++);
        count -= 2;
    }

    if (count > 0)
        sum += *(uint8_t *) addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (~sum);
}

/*
 * Build a TCP pseudo-header and return it's checksum
 */
static uint16_t
tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr, uint8_t *data,
    size_t data_len)
{
    struct pseudo_tcp_header hdr = {0};
    char buf[IP_MAXPACKET];
    char *ptr;
    int hdr_len = 0;
    int i;

    hdr.ip_src_addr = iphdr.ip_src.s_addr;
    hdr.ip_dst_addr = iphdr.ip_dst.s_addr;
    hdr.ip_proto = iphdr.ip_p;
    hdr.ip_payload_len = htons(sizeof(struct tcphdr) + data_len);
    hdr.tcp_sport = tcphdr.th_sport;
    hdr.tcp_dport = tcphdr.th_dport;
    hdr.tcp_seq = tcphdr.th_seq;
    hdr.tcp_ack = tcphdr.th_ack;
    hdr.tcp_offset_reserved = (tcphdr.th_off << 4) + tcphdr.th_x2;
    hdr.tcp_flags = tcphdr.th_flags;
    hdr.tcp_win = tcphdr.th_win;
    hdr.tcp_urp = tcphdr.th_urp;

    ptr = &buf[0];  /* Moving pointer in the buffer */

    /* Copy the pseudo TCP header into the buffer */
    memcpy(ptr, &hdr, sizeof(struct pseudo_tcp_header));
    ptr += sizeof(struct pseudo_tcp_header);
    hdr_len += sizeof(struct pseudo_tcp_header);

    if (data_len > 0) {
        /* Copy data into the buffer */
        memcpy(ptr, data, data_len);
        ptr += data_len;
        hdr_len += data_len;

        /* Pad to the next 16-bit boundary */
        for (i = 0; i < data_len % sizeof(uint16_t); i++, ptr++) {
          *ptr = 0;
          ptr++;
          hdr_len++;
        }
    }

    return (checksum((uint16_t *) buf, hdr_len));
}

/*
 * Set the ARP header default values
 */
static void
set_arp_header(struct arphdr *arphdr)
{
    /* Format of hardware address (16 bits) */
    arphdr->ar_hrd = htons (ARPHRD_ETHER);
    /* Format of protocol address (16 bits) */
    arphdr->ar_pro = htons (ETH_P_IP);
    arphdr->ar_hln = 6; /* Length of hardware address */
    arphdr->ar_pln = 4; /* Length of protocol address */
    arphdr->ar_op = htons (ARPOP_REQUEST); /* ARP opcode (command) */
}

/*
 * Set the IPv4 header with it's header checksum
 */
static void
set_ip_header(packet_type *pck)
{
    int ip_flags[4];

    /* IPv4 header length (4 bits): Number of 32-bit words in header */
    pck->iphdr.ip_hl = sizeof(struct iphdr) / sizeof(uint32_t);
    pck->iphdr.ip_v = 4;  /* Internet Protocol version (4 bits): IPv4 */
    pck->iphdr.ip_tos = 0;  /* Type of service (8 bits) */
    /* Total length of datagram (16 bits): IP header + TCP header */
    pck->iphdr.ip_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) +
        pck->tcp_data_len);
    /* ID sequence number (16 bits) */
    if (ntohs(pck->iphdr.ip_id) == 0)
        pck->iphdr.ip_id = htons(random() % 65535);
    else
        pck->iphdr.ip_id = htons(ntohs(pck->iphdr.ip_id) + 1);

    /* Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram */
    ip_flags[0] = 0;  /* Zero (1 bit) */
    ip_flags[1] = 1;  /* Do not fragment flag (1 bit) */
    ip_flags[2] = 0;  /* More fragments following flag (1 bit) */
    ip_flags[3] = 0;  /* Fragmentation offset (13 bits) */

    pck->iphdr.ip_off = htons(
        (ip_flags[0] << 15) +
        (ip_flags[1] << 14) +
        (ip_flags[2] << 13) +
        ip_flags[3]
    );

    pck->iphdr.ip_ttl = 64;  /* Time-to-Live (8 bits) */
    pck->iphdr.ip_p = IPPROTO_TCP;  /* Transport layer protocol (8 bits) */

    /* Source and Destination IPv4 addresses (32 bits) */
    memcpy(&(pck->iphdr.ip_src), &(pck->src_ip), sizeof(struct in_addr));
    memcpy(&(pck->iphdr.ip_dst), &(pck->dst_ip), sizeof(struct in_addr));

    /* IPv4 header checksum (16 bits): set to 0 when calculating checksum */
    pck->iphdr.ip_sum = 0;
    pck->iphdr.ip_sum = checksum((uint16_t *) &(pck->iphdr),
        sizeof(struct iphdr));
}

/*
 * Set TCP Header
 */
static void
set_tcp_header(uint8_t flags, uint32_t delta_seq, uint32_t ack,
    packet_type *pck)
{
    /* TCP header */
    pck->tcphdr.th_sport = htons(pck->src_port);  /* Source port (16 bits) */
    /* Destination port (16 bits) */
    pck->tcphdr.th_dport = htons(pck->dst_port);
    pck->tcphdr.th_x2 = 0;  /* Reserved (3 bits) */
    /* Data offset (4 bits): size of TCP header in 32-bit words */
    pck->tcphdr.th_off = sizeof(struct tcphdr) / sizeof(uint32_t);
    pck->tcphdr.th_win = htons(29200);  /* Window size (16 bits) */
    /* Urgent pointer (16 bits): only valid if URG flag is set */
    pck->tcphdr.th_urp = htons(0);

    /* TCP flags (9 1 bits): bitmasq */
    pck->tcphdr.th_flags = flags;

    /* Sequence number(32 bits) */
    if (pck->tcphdr.th_seq == 0)
        pck->tcphdr.th_seq = htonl(random());
    else
        pck->tcphdr.th_seq = htonl(ntohl(pck->tcphdr.th_seq) + delta_seq);

    /* Acknowledgement number (32 bits): 0 in first SYN */
    pck->tcphdr.th_ack = htonl(ack);
    /* TCP checksum (16 bits) */
    pck->tcphdr.th_sum = tcp4_checksum(pck->iphdr, pck->tcphdr,
        (uint8_t *) &(pck->tcp_data), pck->tcp_data_len);
}

/*
 * Write ethernet frame to be sent into the wire
 */
static void
set_ethernet_frame(packet_type *pck)
{
    int len;

    /* Ethernet frame length = ethernet header (SRC MAC + DST MAC + eth type) +
     * ethernet data: ARP header or IP+TCP headers */
    len = sizeof(struct ethhdr);

    /* Destination and Source MAC addresses */
    memcpy(pck->eth_frame, pck->dst_mac, 6 * sizeof(uint8_t));
    memcpy(pck->eth_frame + 6, pck->src_mac, 6 * sizeof(uint8_t));

    if (ntohs(pck->arphdr.ar_op) > 0) {
        /* This is an ARP request */

        /* Ethernet type code */
        pck->eth_frame[12] = ETH_P_ARP / 256;
        pck->eth_frame[13] = ETH_P_ARP % 256;

        /* ARP header */
        memcpy (pck->eth_frame + len, &(pck->arphdr), sizeof(struct arphdr));
        len += sizeof(struct arphdr);
        memcpy (pck->eth_frame + len, &(pck->src_mac), 6 * sizeof(uint8_t));
        len += 6 * sizeof(uint8_t);
        memcpy (pck->eth_frame + len, &(pck->src_ip), 4 * sizeof(uint8_t));
        len += 4 * sizeof(uint8_t);
        memcpy (pck->eth_frame + len, &(pck->dst_mac), 6 * sizeof(uint8_t));
        len += 6 * sizeof(uint8_t);
        memcpy (pck->eth_frame + len, &(pck->dst_ip), 4 * sizeof(uint8_t));
        len += 4 * sizeof(uint8_t);

    } else {
        /* This is a TCP/IP request */

        /* Ethernet type code */
        pck->eth_frame[12] = ETH_P_IP / 256;
        pck->eth_frame[13] = ETH_P_IP % 256;

        /* IPv4 header */
        memcpy(pck->eth_frame + len, &(pck->iphdr),
            sizeof(struct iphdr) * sizeof(uint8_t));
        len += sizeof(struct iphdr) * sizeof(uint8_t);

        /* TCP header */
        memcpy(pck->eth_frame + len, &(pck->tcphdr),
            sizeof(struct tcphdr) * sizeof(uint8_t));
        len += sizeof(struct tcphdr) * sizeof(uint8_t);

        /* TCP data */
        if (pck->tcp_data_len > 0) {
            memcpy(pck->eth_frame + len, (uint8_t *) &(pck->tcp_data),
                pck->tcp_data_len * sizeof(uint8_t));
            len += pck->tcp_data_len * sizeof(uint8_t);
        }
    }

    pck->eth_frame_len = len;
}

/*
 * Parse ethernet frame received from the wire
 */
static void
parse_ethernet_frame(packet_type *pck)
{
    size_t pos;

    /* Destination and Source MAC addresses */
    memcpy(pck->dst_mac, pck->eth_frame, 6 * sizeof(uint8_t));
    memcpy(pck->src_mac, pck->eth_frame + 6, 6 * sizeof(uint8_t));

    pos = sizeof(struct ethhdr);

    switch ((pck->eth_frame[12] << 8) + pck->eth_frame[13]) {
    case ETH_P_ARP:
        /* This is an ARP response */

        memcpy (&(pck->arphdr), pck->eth_frame + pos, sizeof(struct arphdr));
        pos += sizeof(struct arphdr);
        memcpy (&(pck->src_mac), pck->eth_frame + pos, 6 * sizeof(uint8_t));
        pos += 6 * sizeof(uint8_t);
        memcpy (&(pck->src_ip), pck->eth_frame + pos, 4 * sizeof(uint8_t));
        pos += 4 * sizeof(uint8_t);
        memcpy (&(pck->dst_mac), pck->eth_frame + pos, 6 * sizeof(uint8_t));
        pos += 6 * sizeof(uint8_t);
        memcpy (&(pck->dst_ip), pck->eth_frame + pos, 4 * sizeof(uint8_t));
        pos += 4 * sizeof(uint8_t);

        memset(&(pck->iphdr), 0, sizeof(struct ip)); /* Reset iphdr */
        memset(&(pck->tcphdr), 0, sizeof(struct tcphdr)); /* Reset tcphdr */

        break;

    case ETH_P_IP:
        /* This is an IPv4 response */
        /* IPv4 header */
        memcpy(&(pck->iphdr), pck->eth_frame + pos,
            sizeof(struct iphdr) * sizeof(uint8_t));
        pos += sizeof(struct iphdr) * sizeof(uint8_t);

        /* TCP header */
        memcpy(&(pck->tcphdr), pck->eth_frame + pos,
            sizeof(struct tcphdr) * sizeof(uint8_t));
        pos += sizeof(struct tcphdr) * sizeof(uint8_t);

        if (pos > pck->eth_frame_len)
            exit_on_error(pck,
                "TCP packet has length %zu, expected at least %zu\n",
                pck->eth_frame_len, pos);
        else if (pos < pck->eth_frame_len) {
            /* TCP data */
            pck->tcp_data_len = (pck->eth_frame_len - pos);
            memcpy(&(pck->tcp_data), pck->eth_frame + pos,
                pck->tcp_data_len * sizeof(uint8_t));
        }

        memcpy(&(pck->src_ip), &(pck->iphdr.ip_src), sizeof(struct in_addr));
        memcpy(&(pck->dst_ip), &(pck->iphdr.ip_dst), sizeof(struct in_addr));

        pck->src_port = ntohs(pck->tcphdr.th_sport);
        pck->dst_port = ntohs(pck->tcphdr.th_dport);

        memset(&(pck->arphdr), 0, sizeof(struct arphdr)); /* Reset arphdr */

        break;

    default:
        /* Unexpected packet, resetting the headers */
        memset(&(pck->iphdr), 0, sizeof(struct ip)); /* Reset iphdr */
        memset(&(pck->tcphdr), 0, sizeof(struct tcphdr)); /* Reset tcphdr */
        memset(&(pck->arphdr), 0, sizeof(struct arphdr)); /* Reset arphdr */

        break;
    }
}

/*
 * Filter a TCP/IPv4 packet to accept only valid replies to sent packets
 */
static uint8_t
filter_tcp_packet(packet_type *send_p, packet_type *recv_p)
{
    size_t mac_size;
    struct sockaddr_ll *send_addr = {0};
    struct sockaddr_ll *recv_addr = {0};

    mac_size = 6 * sizeof(uint8_t);
    send_addr = (struct sockaddr_ll *) &(send_p->st_addr);
    recv_addr = (struct sockaddr_ll *) &(recv_p->st_addr);

    if (recv_addr->sll_ifindex != send_addr->sll_ifindex)
        return (10);  /* Not same iface (L2) */

    if (recv_addr->sll_protocol != send_addr->sll_protocol)
        return (11);  /* Not same physical layer protocol (L2) */

    if (memcmp(recv_addr->sll_addr, send_p->dst_mac, mac_size))
        return (12);  /* Not from same MAC we sent to (L2) */

    if (memcmp(recv_p->src_mac, send_p->dst_mac, mac_size))
        return (20);  /* Not from same MAC we sent to (L3) */

    if (memcmp(recv_p->dst_mac, send_p->src_mac, mac_size))
        return (21);  /* Not to same MAC we sent from (L3) */

    if (recv_p->iphdr.ip_p != IPPROTO_TCP)
        return (30);  /* Not same IP protocol (L3) */

    if (recv_p->src_ip.s_addr != send_p->dst_ip.s_addr)
        return (40);  /* Not from same IP we sent to (L3) */

    if (recv_p->dst_ip.s_addr != send_p->src_ip.s_addr)
        return (41);  /* Not to same IP we sent from (L3) */

    if (recv_p->src_port != send_p->dst_port)
        return (50);  /* Not from same port we sent to (L4) */

    if (recv_p->dst_port != send_p->src_port)
        return (51);  /* Not to same port we send from (L4) */

    if (recv_p->tcphdr.th_flags == TH_ACK ||
        recv_p->tcphdr.th_flags == (TH_ACK | TH_PUSH)) {

        if (ntohl(recv_p->tcphdr.th_ack) != ntohl(send_p->tcphdr.th_seq))
            return (60);  /* Wrong acknowledgement number (L4) */
    } else if (!(recv_p->tcphdr.th_flags & TH_RST)) {
        if (ntohl(recv_p->tcphdr.th_ack) != ntohl(send_p->tcphdr.th_seq) + 1)
            return (61);  /* Wrong acknowledgement number (L4) */
    }

    return (0);
}

/*
 * Filter an ARP packet to accept only valid replies to sent requests
 */
static uint8_t
filter_arp_packet(packet_type *send_p, packet_type *recv_p)
{
    size_t mac_size;
    struct sockaddr_ll *send_addr = {0};
    struct sockaddr_ll *recv_addr = {0};

    mac_size = 6 * sizeof(uint8_t);
    send_addr = (struct sockaddr_ll *) &(send_p->st_addr);
    recv_addr = (struct sockaddr_ll *) &(recv_p->st_addr);

    if (ntohs(send_p->arphdr.ar_op) == 0)
        return (10); /* Not expecting ARP reply */

    if (recv_addr->sll_ifindex != send_addr->sll_ifindex)
        return (20);  /* Not same iface */

    if (recv_addr->sll_protocol != send_addr->sll_protocol)
        return (21);  /* Not same physical layer protocol */

    if (memcmp(recv_p->dst_mac, send_p->src_mac, mac_size))
        return (30);  /* Not to same MAC we sent from */

    if (recv_p->src_ip.s_addr != send_p->dst_ip.s_addr)
        return (31);  /* Not from same IP we sent to */

    if (recv_p->dst_ip.s_addr != send_p->src_ip.s_addr)
        return (32);  /* Not to same IP we sent from */

    return (0);
}

/*
 * Create a dummy TCP socket on a higher port to lock it
 */
static void
create_tcp_socket(struct sockaddr_in *tcp_addr, struct in_addr *src_addr)
{
    int sd;
    struct sockaddr_in addr = {0};
    socklen_t addr_len;

    if ((sd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
        exit_on_perror("Dummy TCP socket() error", NULL);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    memcpy(&(addr.sin_addr), src_addr, sizeof(*src_addr));

    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(sd);
        exit_on_perror("Dummy TCP bind() error", NULL);
    }

    listen(sd, 1);

    addr_len = sizeof(tcp_addr);
    if (getsockname(sd, (struct sockaddr *) tcp_addr, &addr_len) == -1) {
        close(sd);
        exit_on_perror("Dummy TCP getsockname() failed", NULL);
    }

    /* Save the socket descriptor in the static global struct for cleanup */
    rsc_sockets.stream_sd = sd;
}

/*
 * Instantiate a non-blocking RAW socket for a specific protocol
 */
static int
get_raw_socket(int protocol)
{
    int sd;

    if ((sd = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK,
        htons(protocol))) < 0)
        exit_on_perror("RAW socket() failed", NULL);

    return (sd);
}

/*
 * Resolve destination MAC address through ARP request and set it in the packet
 */
static void
set_dst_mac(check_tcp_raw_arguments_type *arguments, packet_type *send_pck,
            packet_type *recv_pck)
{
    int sd, bytes;
    struct sockaddr_ll *addr = {0};

    /* Get a RAW socket for the ARP protocol */
    sd = get_raw_socket(ETH_P_ARP);

    /* Set source address */
    set_src_addr(sd, arguments->iface, send_pck);
    addr = (struct sockaddr_ll *) &(send_pck->st_addr);
    addr->sll_protocol = htons(ETH_P_ARP);

    /* Set broadcast destination MAC address for ARP request */
    memset(send_pck->dst_mac, 0xff, 6 * sizeof(uint8_t));

    set_dst_ip(arguments->real_server, send_pck);
    set_arp_header(&(send_pck->arphdr));
    set_ethernet_frame(send_pck);
    print_arp_packet(RSC_LL_HIGH, send_pck, stdout);

    /* Send ARP request */
    if ((bytes = sendto(sd, send_pck->eth_frame, send_pck->eth_frame_len, 0,
        (struct sockaddr *) addr, sizeof(*addr))) <= 0) {
        close(sd);
        exit_on_perror("ARP request sendto() failed", send_pck);
    }

    /* Listen to ARP reply */
    rsc_sockets.raw_sd = sd;
    receive_packet(send_pck, recv_pck, arguments->timeout);
    if (recv_pck->eth_frame_len == 0)
        exit_on_error(NULL, "No ARP reply received\n");
    memset(&(send_pck->arphdr), 0, sizeof(struct arphdr));

    /* Set destination MAC address */
    memcpy(send_pck->dst_mac, recv_pck->src_mac, 6 * sizeof(uint8_t));

    close(sd);
    rsc_sockets.raw_sd = 0;
}

/*
 * Close all open sockets
 */
void
close_sockets()
{
    if (rsc_sockets.stream_sd > 0)
        close(rsc_sockets.stream_sd);

    if (rsc_sockets.raw_sd > 0)
        close(rsc_sockets.raw_sd);
}

/*
 * Gracefully exit on perror
 */
void
exit_on_perror(char *message, packet_type *pck)
{
    /* Print the last error */
    perror(message);

    /* Print the packet that generated the error, if any */
    if (pck != NULL)
        print_packet_stderr(pck);

    /* Gracefully close all open sockets */
    close_sockets();

    exit(EXIT_FAILURE);
}

/*
 * Check the current role in the role file, if set
 *
 * If the role file contains a 1 as it's first character means that we are
 * on the master of a load balancer cluster, else on a backup one.
 */
uint8_t
is_master(check_tcp_raw_arguments_type *arguments)
{
    FILE *fp;
    int master;

    if (strcmp(arguments->role_file, "") == 0)
        return (1);

    fp = fopen(arguments->role_file, "r");

    if (fp == NULL)
      exit_on_perror("Unable to read role file", NULL);

    master = fgetc(fp);
    fclose(fp);

    if (master == '1')
        return (1);

    return (0);
}

/*
 * Listen until we receive a valid packet or the timeout expires
 */
void
receive_packet(packet_type *send_pck, packet_type *recv_pck, uint32_t timeout)
{
    uint32_t sleep_time_in_ms = 0;
    uint8_t filtered = 0;
    uint8_t received = 0;
    socklen_t fromlen = sizeof(recv_pck->st_addr);
    struct timespec sleep = {0};
    struct timespec sleep_left = {0};

    sleep.tv_sec = 0;
    sleep.tv_nsec = 5000000;  /* 5ms */

    if (rsc_sockets.raw_sd <= 0)
        exit_on_error(NULL, "Unable to receive packet, raw socket not set.\n");

    /* Loop continue receiving packets until we got a valid one */
    while (received == 0) {
        filtered = 0;

        memset(recv_pck->eth_frame, 0x00, sizeof(recv_pck->eth_frame));

        /* Receive a packet */
        if ((recv_pck->eth_frame_len = recvfrom(rsc_sockets.raw_sd,
                recv_pck->eth_frame, IP_MAXPACKET, 0,
                (struct sockaddr *) &(recv_pck->st_addr), &fromlen)
            ) == -1) {

            /* Non blocking socket, retry on EWOULDBLOCK error */
            if (errno == EWOULDBLOCK) {
                /* Stop after retries attempts */
                if (timeout > 0 && sleep_time_in_ms >= timeout) {
                    recv_pck->eth_frame_len = 0;
                    break;
                }

                nanosleep(&sleep, &sleep_left);
                sleep_time_in_ms += (sleep.tv_sec * 1000) +
                    (sleep.tv_nsec / 1000000);
                continue;
            }

            exit_on_perror("recvfrom() failed", NULL);
        }

        parse_ethernet_frame(recv_pck);

        if (ntohs(recv_pck->iphdr.ip_p) > 0) {
            /* Got IP packet */
            if ((filtered = filter_tcp_packet(send_pck, recv_pck)) == 0) {
                received = 1;
                print_tcp_packet(RSC_LL_LOW, recv_pck, stdout);
            } else {
                rsc_log(RSC_LL_LOW, stdout, "Filtered packet (errno: %u)\n",
                    filtered);
                print_tcp_packet(RSC_LL_LOW, recv_pck, stdout);
            }
        } else if (ntohs(recv_pck->arphdr.ar_op) > 0) {
            /* Got ARP packet */
            if ((filtered = filter_arp_packet(send_pck, recv_pck)) == 0) {
                received = 1;
                print_arp_packet(RSC_LL_HIGH, recv_pck, stdout);
            } else {
                rsc_log(RSC_LL_HIGH, stdout,
                    "Filtered ARP packet (errno: %u)\n", filtered);
            }
        }
    }
}

/*
 * Send a TCP packet thorugh a socket
 *
 * Set TCP flags, sequence number, acknowledgement number and verbosity.
 */
void
send_tcp_packet(packet_type *pck, uint8_t flags, uint32_t delta_seq,
    uint32_t ack)
{
    int bytes;

    set_ip_header(pck);
    set_tcp_header(flags, delta_seq, ack, pck);
    set_ethernet_frame(pck);
    print_tcp_packet(RSC_LL_LOW, pck, stdout);

    if (rsc_sockets.raw_sd <= 0)
        exit_on_error(pck, "Unable to send TCP packet, raw socket not set.\n");

    if ((bytes = sendto(rsc_sockets.raw_sd, pck->eth_frame, pck->eth_frame_len,
            0, (struct sockaddr *) &(pck->st_addr), sizeof(pck->st_addr))
        ) <= 0)
        exit_on_perror("TCP packet sendto() failed", pck);

    /* Update the sequence number and cleanup the data */
    if (pck->tcp_data_len > 0) {
        pck->tcphdr.th_seq = htonl(
            ntohl(pck->tcphdr.th_seq) + pck->tcp_data_len);
        memset(&(pck->tcp_data), 0x00, sizeof(pck->tcp_data));
        pck->tcp_data_len = 0;
    }
}

/*
 * Gracefully exit on program error
 */
void
exit_on_error(packet_type *pck, char *message, ...)
{
    va_list arguments;

    /* Print the error message, if any */
    if (message != NULL) {
        va_start(arguments, message);
        vfprintf(stderr, message, arguments);
        va_end(arguments);
    }

    /* Print the packet that generated the error, if any */
    if (pck != NULL)
        print_packet_stderr(pck);

    /* Gracefully close all open sockets */
    close_sockets();

    exit(EXIT_FAILURE);
}

/*
 * Close an open TCP connection
 */
void
close_tcp_connection(check_tcp_raw_arguments_type *arguments,
    packet_type *send_pck, packet_type *recv_pck)
{
    /* Start the half-way TCP close: FIN/ACK */
    send_tcp_packet(send_pck, TH_FIN | TH_ACK, 0,
        ntohl(recv_pck->tcphdr.th_seq) + recv_pck->tcp_data_len);

    /* Wait for the FIN/ACK */
    receive_packet(send_pck, recv_pck, arguments->timeout);
    if (recv_pck->eth_frame_len == 0)
        exit_on_error(NULL, "No FIN/ACK reply received\n");
    if (recv_pck->tcphdr.th_flags != (TH_FIN | TH_ACK))
        exit_on_error(recv_pck,
            "Received wrong packet, expected FIN/ACK:\n");

    /* Send final ACK */
    send_tcp_packet(send_pck, TH_ACK, 1, ntohl(recv_pck->tcphdr.th_seq) + 1);
}

/*
 * Perform a TCP 3-way handshake to open the connection: SYN - SYN/ACK - ACK
 */
void
open_raw_tcp_connection(check_tcp_raw_arguments_type *arguments,
    packet_type *send_pck, packet_type *recv_pck)
{
    struct sockaddr_ll *addr = {0};
    struct sockaddr_in tcp_addr = {0};

    /* Initialize the random generator */
    srandom(time(NULL));

    /* Resolve the destination MAC through ARP */
    set_dst_mac(arguments, send_pck, recv_pck);

    /* Create a dummy TCP socket on a higher port */
    create_tcp_socket(&tcp_addr, &(send_pck->src_ip));
    /* Set source port based on the higher port got for the dummy socket */
    send_pck->src_port = ntohs(tcp_addr.sin_port);

    /* Set the addres structure needed by socket functions */
    addr = (struct sockaddr_ll *) &(send_pck->st_addr);
    addr->sll_protocol = htons(ETH_P_IP);

    /* Get a RAW socket for the IPv4 protocol */
    rsc_sockets.raw_sd = get_raw_socket(ETH_P_IP);

    /* Bind the socket to a local address, reduce the # of packets received */
    if (bind(rsc_sockets.raw_sd, (struct sockaddr *) addr,
        sizeof(*addr)) == -1)
        exit_on_perror("RAW bind() failed", NULL);

    /* Set destination IP and port */
    set_dst_ip(arguments->virtual_ip, send_pck);
    send_pck->dst_port = arguments->port;

    /* Start the 3-way TCP handshake: SYN */
    send_tcp_packet(send_pck, TH_SYN, 0, 0);

    /* Wait for the SYN/ACK */
    receive_packet(send_pck, recv_pck, arguments->timeout);
    if (recv_pck->eth_frame_len == 0)
        exit_on_error(NULL, "No SYN/ACK reply received\n");
    if (recv_pck->tcphdr.th_flags != (TH_SYN | TH_ACK))
        exit_on_error(recv_pck, "Received wrong packet, expected SYN/ACK:\n");

    /* Complete the 3-way TCP handshake: ACK */
    send_tcp_packet(send_pck, TH_ACK, 1, ntohl(recv_pck->tcphdr.th_seq) + 1);
}

/*
 * Open a normal (non-RAW) TCP connection
 */
int
open_tcp_connection(check_tcp_raw_arguments_type *arguments)
{
    struct sockaddr_in addr = {0};
    struct sockaddr_in dst_addr = {0};

    if ((rsc_sockets.stream_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        exit_on_perror("TCP socket() error", NULL);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(arguments->port);

    resolve_dst(arguments->real_server, &dst_addr);
    memcpy(&(addr.sin_addr), (struct in_addr *) &(dst_addr.sin_addr),
        sizeof(dst_addr.sin_addr));

    if (connect(rsc_sockets.stream_sd, (struct sockaddr *) &addr,
            sizeof(addr)) < 0)
        exit_on_perror("TCP connect() error", NULL);

    rsc_log(RSC_HL_LOW, stdout,
        "* Connected to %s:%d\n", inet_ntoa(addr.sin_addr), arguments->port);

    return (rsc_sockets.stream_sd);
}

/*
 * Quickly abort the TCP connection sending a RST/ACK
 */
void
abort_tcp_connection(packet_type *send_pck, packet_type *recv_pck)
{
    /* We are done, quickly close the connection: RST/ACK */
    send_tcp_packet(send_pck, TH_RST | TH_ACK, 0,
        ntohl(recv_pck->tcphdr.th_seq) + 1);

    /* Ensure we didn't get a reply */
    receive_packet(send_pck, recv_pck, 25);
    if (recv_pck->eth_frame_len != 0)
        exit_on_error(recv_pck,
            "Not expecting reply after the connection was aborted:\n");
}

/*
 * Perform a TCP check based on the load balancer role
 */
void
tcp_check(check_tcp_raw_arguments_type *arguments)
{
    packet_type send_pck = {0};
    packet_type recv_pck = {0};

    /* Open the TCP connection */
    if (is_master(arguments) == 1) {
        open_raw_tcp_connection(arguments, &send_pck, &recv_pck);

        /* We are done, quickly close the connection */
        abort_tcp_connection(&send_pck, &recv_pck);
    } else
        (void)open_tcp_connection(arguments);

    /* Close sockets */
    close_sockets();
}
