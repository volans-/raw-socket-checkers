/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        HTTP library.
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

#define _GNU_SOURCE 1           /* for TEMP_FAILURE_RETRY */

#include <arpa/inet.h>          /* inet_pton(), inet_ntop() */

#include <openssl/md5.h>

#include <errno.h>              /* errno, perror() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>             /* strcpy, memset(), memcpy() */
#include <unistd.h>             /* close(), TEMP_FAILURE_RETRY */

#include "common.h"

/*
 * Abort the TCP connection
 *
 * Reset the TCP connection and exit printing a message and optionally the
 * TCP packet that was received.
 */
static void
abort_connection(packet_type *send_pck, packet_type *recv_pck, char *message,
    uint8_t log_pck)
{
    if (send_pck != NULL) {
        abort_tcp_connection(send_pck, recv_pck);

        rsc_log(RSC_HL_LOW, stdout, "* Reset connection to %s\n",
            inet_ntoa(send_pck->dst_ip));
    }

    if (log_pck)
        exit_on_error(recv_pck, message);
    else
        exit_on_error(NULL, message);
}

/*
 * Parse an HTTP status line into an HTTP Response struct (http_response_type)
 */
static void
parse_status_line(char *line, http_response_type *res)
{
    rsc_log(RSC_HL_LOW, stdout, "< %s\n", line);

    (void) strtok(line, "/");
    res->version = strtok(NULL, " ");
    res->status_code = (uint16_t) atoi(strtok(NULL, " "));
    res->status_msg = strtok(NULL, "");
}

/*
 * Parse an HTTP header line into an HTTP header struct (http_header_type)
 */
static void
parse_header_line(char *line, http_header_type *hdr)
{
    rsc_log(RSC_HL_LOW, stdout, "< %s\n", line);

    hdr->name = strtok(line, ":");
    hdr->value = strtok(NULL, "");
}

/*
 * Split the given line at the CRLF terminating it with null bytes.
 */
static char *
extract_line(char *line)
{
    char *line_end;

    line_end = strstr(line, "\r\n");
    if (line_end == NULL)
        return (0);

    /* Terminate the line */
    *line_end = '\0';
    line_end++;
    *line_end = '\0';
    line_end++;

    return (line_end);
}

/*
 * Parse an HTTP response into an HTTP Response struct (http_response_type)
 */
static void
parse_http_response(char *data, http_response_type *res)
{
    char *line_end;
    char *line;
    unsigned char *hash;
    size_t i, len;

    /* Put the pointer at the start of the data */
    line = data;
    line_end = 0;

    /* Extract the status line */
    line_end = extract_line(line);
    parse_status_line(line, res);
    line = line_end;

    /* Extract all headers */
    for (i = 0; i < RSC_HEADERS_MAX_LEN; i++) {
        line_end = extract_line(line);

        /* Check for the end of headers */
        if (line[0] == '\0') {
            line = line_end;
            break;
        }

        parse_header_line(line, &(res->headers[i]));
        line = line_end;
    }

    if (i == RSC_HEADERS_MAX_LEN - 1)
        exit_on_error(NULL, "Too many HTTP headers (%u), aborting\n",
            RSC_HEADERS_MAX_LEN);  /* TODO: improve error handling */

    rsc_log(RSC_HL_LOW, stdout, "< \n");

    /* Extract the body */
    res->body = line;
    len = strlen(res->body);

    rsc_log(RSC_HL_HIGH, stdout, "%s", res->body);
    if (res->body[(len - 1)] != '\n')
        rsc_log(RSC_HL_HIGH, stdout, "\n* HTTP Body missing newline at the end"
                ", added for logging purposes\n");

    if (check_verbosity(RSC_HL_HIGH, RSC_NOOP_VERBOSITY) == 0)
        rsc_log(RSC_HL_LOW, stdout,
            "* Skipping HTTP body, verbosity level too low\n");

    hash = MD5((unsigned char *) res->body, len, NULL);

    for(i = 0; i < 16; i++) {
        sprintf(res->body_hash + (i * 2), "%02x", hash[i]);
    }
    res->body_hash[33] = '\0';

    rsc_log(RSC_HL_LOW, stdout, "* HTTP Body MD5 is %s\n", res->body_hash);
}

/*
 * Open the TCP connection and log it using the cURL format.
 */
static void
open_raw_connection(check_tcp_raw_arguments_type *arguments,
    packet_type *send_pck, packet_type *recv_pck)
{
    size_t i;

    /* Open the TCP connection */
    open_raw_tcp_connection(arguments, send_pck, recv_pck);

    rsc_log(RSC_HL_LOW, stdout, "* Connected to (");
    /* Destination MAC address */
    for (i=0; i<5; i++) {
        rsc_log(RSC_HL_LOW, stdout, "%02x:", send_pck->dst_mac[i]);
    }
    rsc_log(RSC_HL_LOW, stdout, "%02x) %s:%u\n", send_pck->dst_mac[5],
        inet_ntoa(send_pck->dst_ip), send_pck->dst_port);
}

/*
 * Check that the HTTP Response has the requested HTTP Header.
 */
static uint8_t
validate_http_header(char *name, char *value, http_response_type *recv_http)
{
    size_t i;

    for (i = 0; i < RSC_HEADERS_MAX_LEN; i++) {
        if (recv_http->headers[i].name == NULL)
            break;

        if (strcmp(recv_http->headers[i].name, name) == 0 &&
            strcmp(recv_http->headers[i].value, value) == 0)
            return (0);
    }

    return (1);
}

/*
 * Validate the HTTP Response based on the arguments.
 */
static uint8_t
validate_http_response(check_http_raw_arguments_type *arguments,
    http_response_type *recv_http)
{
    size_t i;
    uint8_t checks = 0;

    /* Validate Response status code */
    if (arguments->response.status_code != 0) {
        checks++;
        if (recv_http->status_code != arguments->response.status_code) {
            fprintf(stderr, "Expected HTTP status code %u, got %u\n",
                arguments->response.status_code, recv_http->status_code);
            return (1);
        }
    }

    /* Validate Response headers */
    for (i = 0; i < RSC_HEADERS_MAX_LEN; i++) {
        if (arguments->response.headers[i].name == NULL)
            break;

        checks++;
        if (validate_http_header(arguments->response.headers[i].name,
            arguments->response.headers[i].value, recv_http) != 0) {

                checks++;
            fprintf(stderr, "Missing HTTP Header '%s:%s' in Response\n",
                arguments->response.headers[i].name,
                arguments->response.headers[i].value);
            return (1);
        }
    }

    /* Validate Response body hash */
    if (strlen(arguments->response.body_hash) > 0) {
        checks++;
        if (strcmp(arguments->response.body_hash, recv_http->body_hash) != 0) {
            fprintf(stderr, "Expected HTTP Body MD5 to be '%s', got '%s'\n",
                arguments->response.body_hash, recv_http->body_hash);
            return (1);
        }
    }

    /* Validate Response body */
    if (arguments->response.body != NULL) {
        checks++;
        if (strcmp(arguments->response.body, recv_http->body) != 0) {
            fprintf(stderr, "Expected HTTP Body to be:\n%s\nGot:\n%s\n",
                arguments->response.body, recv_http->body);
            return (1);
        }
    }

    if (checks > 0)
        return (0);

    fprintf(stderr, "Unable to validate HTTP Response, no check specified");
    return (1);
}

/*
 * Set the HTTP GET Request.
 */
static size_t
set_http_get(check_http_get_raw_arguments_type *arguments, char data[])
{
    size_t len = 0;
    size_t i;

    len = sprintf(data,
        "GET %s HTTP/1.1\r\nUser-Agent: %s\r\nHost: %s\r\n\r\n",
        arguments->path, RSC_USER_AGENT, arguments->host);

    if (len <= 0)
        abort_connection(NULL, NULL, "Unable to build HTTP Request\n", 0);

    rsc_log(RSC_HL_LOW, stdout, "> ");
    for (i = 0; i < len; i++) {
        switch (data[i]) {
        case '\r':
            break;
        case '\n':
            if (i == (len - 1))
                rsc_log(RSC_HL_LOW, stdout, "\n");
            else
                rsc_log(RSC_HL_LOW, stdout, "\n> ");

            break;
        default:
            rsc_log(RSC_HL_LOW, stdout, "%c", data[i]);
            break;
        }
    }

    return (len);
}

/*
 * Send the HTTP GET Request.
 */
static void
send_http_get(check_http_get_raw_arguments_type *arguments,
    packet_type *send_pck, packet_type *recv_pck)
{
    /* Send the request */
    send_pck->tcp_data_len = set_http_get(arguments, send_pck->tcp_data);

    send_tcp_packet(send_pck, TH_PUSH | TH_ACK, 0,
        ntohl(recv_pck->tcphdr.th_seq) + 1);

    /* Expect an ACK */
    receive_packet(send_pck, recv_pck, arguments->tcp.timeout);
    if (recv_pck->tcphdr.th_flags != TH_ACK)
        abort_connection(send_pck, recv_pck,
            "Received wrong packet, expected ACK:\n", 1);
}

/*
 * Build the HTTP Request.
 */
static size_t
build_http_request(check_http_raw_arguments_type *arguments, char data[])
{
    size_t i, added, len;

    len = 0;

    /* Build the Request */
    added = sprintf(data, "%s %s HTTP/1.1\r\nUser-Agent: %s\r\nHost: %s\r\n",
        arguments->method, arguments->path, RSC_USER_AGENT, arguments->host);

    if (added <= 0)
        abort_connection(NULL, NULL, "Unable to build HTTP Request\n", 0);
    len += added;

    for (i = 0; i < RSC_HEADERS_MAX_LEN; i++) {
        if (arguments->headers[i].name == NULL)
            break;

        added = sprintf(data + len, "%s:%s\r\n", arguments->headers[i].name,
            arguments->headers[i].value);

        if (added <= 0)
            abort_connection(NULL, NULL,
                "Unable to add Headers to the HTTP Request\n", 0);
        len += added;
    }

    added = sprintf(data + len, "\r\n");
    if (added <= 0)
        abort_connection(NULL, NULL, "Unable to complete HTTP Request\n", 0);
    len += added;

    rsc_log(RSC_HL_LOW, stdout, "> ");
    for (i = 0; i < len; i++) {
        switch (data[i]) {
        case '\r':
            break;
        case '\n':
            if (i == (len - 1))
                rsc_log(RSC_HL_LOW, stdout, "\n");
            else
                rsc_log(RSC_HL_LOW, stdout, "\n> ");

            break;
        default:
            rsc_log(RSC_HL_LOW, stdout, "%c", data[i]);
            break;
        }
    }

    return (len);
}

/*
 * Build and send the HTTP Request.
 */
static void
send_http_request(check_http_raw_arguments_type *arguments,
    packet_type *send_pck, packet_type *recv_pck)
{
    send_pck->tcp_data_len = build_http_request(arguments, send_pck->tcp_data);

    send_tcp_packet(send_pck, TH_PUSH | TH_ACK, 0,
        ntohl(recv_pck->tcphdr.th_seq) + 1);

    /* Expect an ACK */
    receive_packet(send_pck, recv_pck, arguments->tcp.timeout);
    if (recv_pck->tcphdr.th_flags != TH_ACK)
        abort_connection(send_pck, recv_pck,
            "Received wrong packet, expected ACK:\n", 1);
}

/*
 * Perform an HTTP GET check using RAW socket.
 *
 * It performs an HTTP GET of PATH for HOST using a RAW socket sending the
 * packets from the SOURCE_INTERFACE to the MAC address of the REAL_SERVER
 * with a TCP/IP destination set to VIRTUAL_IP and PORT. The MD5 hash of
 * the response body is then compared to VALUE for the check to be successful.
 */
static uint8_t
http_get_raw_check(check_http_get_raw_arguments_type *arguments)
{
    packet_type send_pck = {0};
    packet_type recv_pck = {0};
    http_response_type recv_http = {0};
    uint8_t ret = 0;

    open_raw_connection(&(arguments->tcp), &send_pck, &recv_pck);

    send_http_get(arguments, &send_pck, &recv_pck);

    /* Expect an HTTP response */
    receive_packet(&send_pck, &recv_pck, arguments->tcp.timeout);
    if (recv_pck.eth_frame_len == 0)
        abort_connection(&send_pck, &recv_pck, "No PUSH/ACK reply received\n",
            0);

    if (recv_pck.tcphdr.th_flags != (TH_PUSH | TH_ACK))
        abort_connection(&send_pck, &recv_pck,
            "Received wrong packet, expected PUSH/ACK:\n", 1);

    /* Parse the HTTP response and ACK it */
    parse_http_response((char *) &recv_pck.tcp_data, &recv_http);

    send_tcp_packet(&send_pck, TH_ACK, 0,
        ntohl(recv_pck.tcphdr.th_seq) + recv_pck.tcp_data_len);

    /* Verify that the response is the expected one */
    if (recv_http.status_code < 200 || recv_http.status_code >= 300) {
        fprintf(stderr, "Expected 2XX HTTP status code, got %u\n",
            recv_http.status_code);
        ret = 1;
    }

    if (strcmp(arguments->value, (char *) recv_http.body_hash) != 0) {
        fprintf(stderr, "Expected HTTP Body MD5 %s, got %s\n",
            arguments->value, recv_http.body_hash);
        ret = 1;
    }

    /* We are done, close the connection */
    close_tcp_connection(&(arguments->tcp), &send_pck, &recv_pck);

    rsc_log(RSC_HL_LOW, stdout, "* Closed connection to %s\n",
        inet_ntoa(send_pck.dst_ip));

    /* Close sockets */
    close_sockets();

    return (ret);
}

/*
 * Perform an HTTP GET check using TCP socket.
 *
 * It performs an HTTP GET of PATH for HOST using a TCP socket sending the
 * packets from the SOURCE_INTERFACE to the the REAL_SERVER and PORT. The MD5
 * hash of the response body is then compared to VALUE for the check to be
 * successful.
 */
static uint8_t
http_get_tcp_check(check_http_get_raw_arguments_type *arguments)
{
    http_response_type recv_http = {0};
    char data[IP_MAXPACKET];
    size_t data_len = 0;
    uint8_t ret = 0;
    int sd;

    sd = open_tcp_connection(&(arguments->tcp));

    data_len = set_http_get(arguments, data);

    if (TEMP_FAILURE_RETRY(write(sd, data, data_len)) < 0)
        exit_on_perror("Unable to send GET request", NULL);

    /* Expect an HTTP response */
    memset(data, 0, IP_MAXPACKET);
    if (TEMP_FAILURE_RETRY(read(sd, &data[0], IP_MAXPACKET)) < 0)
        exit_on_perror("Didn't get any response", NULL);

    /* Parse the HTTP response and ACK it */
    parse_http_response((char *) &data, &recv_http);

    /* Verify that the response is the expected one */
    if (recv_http.status_code < 200 || recv_http.status_code >= 300) {
        fprintf(stderr, "Expected 2XX HTTP status code, got %u\n",
            recv_http.status_code);
        ret = 1;
    }

    if (strcmp(arguments->value, (char *) recv_http.body_hash) != 0) {
        fprintf(stderr, "Expected HTTP Body MD5 %s, got %s\n",
            arguments->value, recv_http.body_hash);
        ret = 1;
    }

    /* Close sockets */
    close_sockets();

    rsc_log(RSC_HL_LOW, stdout, "* Closed connection\n");

    return (ret);
}

/*
 * Perform an HTTP check using TCP socket.
 */
static uint8_t
http_tcp_check(check_http_raw_arguments_type *arguments)
{
    http_response_type recv_http = {0};
    char data[IP_MAXPACKET];
    size_t data_len = 0;
    uint8_t ret;
    int sd;

    sd = open_tcp_connection(&(arguments->tcp));

    data_len = build_http_request(arguments, data);

    if (TEMP_FAILURE_RETRY(write(sd, data, data_len)) < 0)
        exit_on_perror("Unable to send GET request", NULL);

    /* Expect an HTTP response */
    memset(data, 0, IP_MAXPACKET);
    if (TEMP_FAILURE_RETRY(read(sd, &data[0], IP_MAXPACKET)) < 0)
        exit_on_perror("Didn't get any response", NULL);

    /* Parse the HTTP response and ACK it */
    parse_http_response((char *) &data, &recv_http);

    ret = validate_http_response(arguments, &recv_http);

    /* Close sockets */
    close_sockets();

    rsc_log(RSC_HL_LOW, stdout, "* Closed connection\n");

    return (ret);
}

/*
 * Perform an HTTP check using RAW socket.
 */
static uint8_t
http_raw_check(check_http_raw_arguments_type *arguments)
{
    packet_type send_pck = {0};
    packet_type recv_pck = {0};
    http_response_type recv_http = {0};
    uint8_t ret;

    open_raw_connection(&(arguments->tcp), &send_pck, &recv_pck);

    send_http_request(arguments, &send_pck, &recv_pck);

    /* Expect an HTTP response */
    receive_packet(&send_pck, &recv_pck, arguments->tcp.timeout);
    if (recv_pck.eth_frame_len == 0)
        abort_connection(&send_pck, &recv_pck, "No PUSH/ACK reply received\n",
            0);

    if (recv_pck.tcphdr.th_flags != (TH_PUSH | TH_ACK))
        abort_connection(&send_pck, &recv_pck,
            "Received wrong packet, expected PUSH/ACK:\n", 1);

    /* Parse the HTTP response and ACK it */
    parse_http_response((char *) &recv_pck.tcp_data, &recv_http);

    send_tcp_packet(&send_pck, TH_ACK, 0,
        ntohl(recv_pck.tcphdr.th_seq) + recv_pck.tcp_data_len);

    ret = validate_http_response(arguments, &recv_http);

    /* We are done, close the connection */
    close_tcp_connection(&(arguments->tcp), &send_pck, &recv_pck);

    rsc_log(RSC_HL_LOW, stdout, "* Closed connection to %s\n",
        inet_ntoa(send_pck.dst_ip));

    /* Close sockets */
    close_sockets();

    return (ret);
}

/*
 * Perform an HTTP check using RAW or TCP socket based on the LB role.
 */
uint8_t
http_check(check_http_raw_arguments_type *arguments)
{
    uint8_t ret;

    if (is_master(&(arguments->tcp)) == 1)
        ret = http_raw_check(arguments);
    else
        ret = http_tcp_check(arguments);

    return (ret);
}

/*
 * Perform an HTTP GET check using RAW or TCP socket based on the LB role.
 */
uint8_t
http_get_check(check_http_get_raw_arguments_type *arguments)
{
    uint8_t ret;

    if (is_master(&(arguments->tcp)) == 1)
        ret = http_get_raw_check(arguments);
    else
        ret = http_get_tcp_check(arguments);

    return (ret);
}
