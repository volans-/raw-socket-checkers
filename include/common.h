/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        Common C header file.
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

#ifndef _RSC_COMMON_HEADER
# define _RSC_COMMON_HEADER 1

#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>         /* struct arpreq, ARP-related defines */
#include <netinet/tcp.h>        /* struct tcphdr */
#include <netinet/ip.h>         /* struct ip, IP_MAXPACKET */

#include <stdio.h>

#define RSC_USER_AGENT "raw-socket-checkers/1.0"
#define RSC_HEADERS_MAX_LEN 32

/*
 * Verbosity levels enum
 */
typedef enum {
    RSC_NOOP_VERBOSITY = -1, /* Don't touch the verbosity level */
    RSC_NO_VERBOSITY,  /* No verbosity */
    RSC_HL_LOW,  /* Higher layers low verbosity */
    RSC_HL_HIGH,  /* Higher layers high verbosity */
    RSC_LL_LOW,  /* Lower layers low verbosity */
    RSC_LL_HIGH,  /* Lower layers high verbosity */
} verbosity_level_type;

/*
 * Structure for each HTTP header
 */
typedef struct {
    char *name;
    char *value;
} http_header_type;

/*
 * Structure with all the information relative to an HTTP response.
 */
typedef struct {
    uint16_t status_code;  /* HTTP status code */
    char *version;  /* HTTP version */
    char *status_msg;  /* HTTP status message */
    http_header_type headers[RSC_HEADERS_MAX_LEN];  /* Array of HTTP headers */
    char *body;  /* HTTP body */
    char body_hash[33];  /* MD5 Hash of the body */
} http_response_type;

/*
 *check_tcp_raw arguments and options
 */
typedef struct {
    uint16_t port;  /* TCP port to check on the real server */
    char iface[40];  /* Ethernet interface name to send packets from */
    char real_server[256];  /* IPv4 or hostname of the real server to check */
    char virtual_ip[256];  /* IPv4 or hostname of the VIP to check */
    char role_file[256];  /* Path to the file where the LB role is saved */
    uint8_t clean_close;  /* Whether to close the connection in a clean way */
    verbosity_level_type verbosity;  /* Verbosity level */
    uint32_t timeout;  /* Socket timeout for receiving packets in ms */
} check_tcp_raw_arguments_type;

/*
 * check_http_get_raw arguments and options
 */
typedef struct {
    char host[256];  /* HTTP Host header, hostname or IPv4 */
    char path[1024];  /* HTTP Path to GET, with leading slash (/) */
    char value[1024];  /* Expected HTTP response body MD5 hash */
    check_tcp_raw_arguments_type tcp;  /* Arguments for TCP and lower layers */
} check_http_get_raw_arguments_type;

/*
 * check_http_raw arguments and options
 */
typedef struct {
    char host[256];  /* HTTP Host header, hostname or IPv4 */
    char path[1024];  /* HTTP Request Path, with leading slash (/) */
    char method[8];  /* HTTP Request Method */
    check_tcp_raw_arguments_type tcp;  /* Arguments for TCP and lower layers */
    /* Array of HTTP headers for the request */
    http_header_type headers[RSC_HEADERS_MAX_LEN];
    http_response_type response;  /* Expected response object */
} check_http_raw_arguments_type;

/*
 * Structure with all the information relative to a single packet.
 *
 * Used to create packets to send from RAW information or to store the
 * packet's information after a received packet is parsed.
 */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    struct tcphdr tcphdr;
    struct ip iphdr;
    struct arphdr arphdr;
    struct sockaddr_storage st_addr;  /* Needed by sendto(), recvfrom() */
    uint8_t eth_frame[IP_MAXPACKET];
    size_t eth_frame_len;
    char tcp_data[IP_MAXPACKET];
    size_t tcp_data_len;
} packet_type;

/*
 * Check and set the verbosity level
 */
uint8_t check_verbosity(verbosity_level_type, verbosity_level_type);

/*
 * Print line to file descriptor based on verbosity
 */
void rsc_log(verbosity_level_type, FILE *, char *, ...);

/*
 * Quickly abort the TCP connection sending a RST/ACK
 */
void abort_tcp_connection(packet_type *, packet_type *);

/*
 * Open a normal (non-RAW) TCP connection
 */
int open_tcp_connection(check_tcp_raw_arguments_type *);

/*
 * Perform a TCP 3-way handshake to open the connection: SYN - SYN/ACK - ACK
 */
void open_raw_tcp_connection(check_tcp_raw_arguments_type *, packet_type *,
    packet_type *);

/*
 * Close an open TCP connection
 */
void close_tcp_connection(check_tcp_raw_arguments_type *, packet_type *,
    packet_type *);

/*
 * Gracefully exit on program error
 */
void exit_on_error(packet_type *, char *, ...);

/*
 * Send a TCP packet thorugh a socket
 */
void send_tcp_packet(packet_type *, uint8_t, uint32_t, uint32_t);

/*
 * Listen until we receive a valid packet or the timeout expires
 */
void receive_packet(packet_type *, packet_type *, uint32_t);

/*
 * Close all open sockets
 */
void close_sockets();

/*
 * Gracefully exit on perror
 */
void exit_on_perror(char *, packet_type *);

/*
 * Check the current role in the role file, if set
 */
uint8_t is_master(check_tcp_raw_arguments_type *);

#endif
