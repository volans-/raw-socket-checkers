/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        CLI argument parser for the check_http_raw check.
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

#include <sys/types.h>

#include <netinet/in.h>

#include <argp.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

#define CHECK_HTTP_GET_RAW_ARGS 6  /* Number of mandatory arguments */

/* Program documentation */
static char doc[] = "\ncheck_http_raw -- an HTTP checker with RAW sockets\n\n"
    "It performs an HTTP Request of PATH for HOST using a RAW socket sending "
    "the packets from the SOURCE_INTERFACE to the MAC address of the "
    "REAL_SERVER with a TCP/IP destination set to VIRTUAL_IP and PORT. The "
    "HTTP Method and Request Headers can be customized. The Response status, "
    "Response Headers, Response Body and Response Body MD5 can be verified "
    "for the check to be successful.\n\n"
    "This is suitable to be used as a check for load balancers in direct "
    "routing mode (LVS-DR) to ensure that the real server is indeed answering "
    "to packets with the VIRTUAL_IP destination IP.\n\n"
    "Example:\ncheck_http_raw -vv -t 500 -r /var/run/lvs.role -S 200 "
    "-A d36f8f9425c4a8000ad9c4a97185aca5 -R \"Server: nginx/1.8.0\" eth0 "
    "10.0.0.42 10.0.0.100 80 www.example.com /healthcheck\n\n"
    "Example to calculate the MD5 of the HTTP Response:\n"
    "curl -s -H \"Host: www.example.com\" http://10.0.0.42/healthcheck | "
    "md5sum\n\n"
    "============================\nEXIT STATUS\n----------------------------"
    "\n\n"
    "EXIT_SUCCESS on success, EXIT_FAILURE on failure.\n\n"
    "============================\nPARAMETERS\n----------------------------"
    "\n\n"
    "  SOURCE_IFACE    the name of the network interface to use to send the "
        "packets\n                  from (i.e. eth0).\n\n"
    "  REAL_SERVER     IPv4 or hostname of the real server to check. Only "
        "used to\n                  get it's MAC address (i.e. 10.0.0.42).\n\n"
    "  VIRTUAL_IP      IPv4 or hostname of the virtual IP for which the check"
        "\n                  should be performed, used as destination IP in "
        "the TCP\n                  packets (i.e. 10.0.0.100)\n\n"
    "  PORT            TCP port number to use for the check (i.e. 80)\n\n"
    "  HOST            Virtual host to made the request to, becomes the HTTP "
        "Host\n                  header in the request "
        "(i.e. www.example.com)\n"
    "  PATH            HTTP Resource to request, with leading slash\n"
        "                  (i.e. /healthcheck)\n"
    "============================\nOPTIONS\n----------------------------\n"
    "At least one of [-S, -R, -B, -A] must be set to validate the HTTP "
    "Response.\n";

/* Mandatory arguments */
static char args_doc[] =
    "SOURCE_IFACE REAL_SERVER VIRTUAL_IP PORT HOST PATH";

/* Available options */
static struct argp_option options[] = {
    {"method", 'M', "METHOD", 0, "The HTTP Method to use for the HTTP "
        "Request. Accepted values are: GET, HEAD. [Default: GET]"
    },
    {"header", 'H', "HEADER", 0, "Additional HTTP Header to send in the "
        "request in the format \"Name: Value\". Can be specified multiple "
        "times to add more headers."
    },
    {"response-header", 'R', "HEADER", 0, "HTTP Header in the response that "
        "has to match for the check to be successful, in the format \"Name: "
        "Value\". Can be specified multiple times to add more headers."
    },
    {"status-code", 'S', "STATUS_CODE", 0, "The expected HTTP Status Code "
        "for the check to be successful."
    },
    {"body", 'B', "BODY", 0, "The expected HTTP Body as string for the check "
        "to be successful."
    },
    {"hash", 'A', "MD5SUM", 0, "The MD5 hash of the expected HTTP Response "
        "Body for the check to be successful."
    },
    {"role-file", 'r', "FILE", 0, "Path of the file that contains the current "
        "role of the load balancer. Only the first character is read, "
        "accepted values are: 1 => MASTER, anything else => BACKUP. When this "
        "parameter is set the checks on a BACKUP server are done using the "
        "real server IP instead of the VIRTUAL_IP with a standard TCP socket."
    },
    {"timeout", 't', "MILLISECONDS", 0, "Timeout for each REAL_SERVER reply "
        "in ms.\nTo disable set to 0. [Default: 1000]"
    },
    {"verbose", 'v', 0, 0, "Produce increasing verbose output to standard "
        "error based on the number of occurrences:\n"
        "-v)    CLI parameters and HTTP response summary\n"
        "-vv)   Print also the full HTTP response body\n"
        "-vvv)  Print also all TCP packets\n"
        "-vvvv) Print also all ARP packets"
    },
    { 0 }
};

static size_t request_headers_len = 0;  /* Counter of the -H options */
static size_t response_headers_len = 0;  /* Counter of the -R options */

/*
 * Parse a single option
 */
static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    static char methods[] = "GET,HEAD";
    char *method, *methods_copy;
    uint8_t found;
    uint16_t status_code;

    /* The input argument from argp_parse is a pointer to our structure. */
    check_http_raw_arguments_type *arguments = state->input;

    switch (key) {
    case 'v': arguments->tcp.verbosity++; break;
    case 't': arguments->tcp.timeout = (uint32_t) atoi(arg); break;
    case 'r': strcpy(arguments->tcp.role_file, arg); break;
    case 'B': arguments->response.body = arg; break;

    case 'A':
        if (strlen(arg) != 32)
            argp_error(state, "Invalid hash length '%zu' for option (-A, "
                "--hash), expected 32 characters MD5 string.", strlen(arg));

        strcpy(arguments->response.body_hash, arg);
        break;

    case 'S':
        status_code = (uint16_t)atoi(arg);

        if (status_code < 100 || status_code >= 600)
            argp_error(state, "Invalid value '%u' for option (-S, "
                "--status-code), expected 100 <= value < 600.", status_code);

        arguments->response.status_code = status_code;
        break;

    case 'M':
        found = 0;

        methods_copy = calloc(strlen(methods) + 1, sizeof(char));
        strcpy(methods_copy, methods);

        method = strtok(methods_copy, ",");
        while (method != NULL) {
            if (strcmp(method, arg) == 0) {
                strcpy(arguments->method, arg);
                found++;
                break;
            }
            method = strtok(NULL, ",");
        }

        free(methods_copy);

        if (found == 0)
            argp_error(state, "Invalid value '%s' for option (-M, --method), "
                "expected one of [%s].", arg, methods);

        break;

    case 'H':
        if (request_headers_len == RSC_HEADERS_MAX_LEN)
            argp_error(state, "Too many HTTP Request Headers (%d -H).",
                RSC_HEADERS_MAX_LEN + 1);

        arguments->headers[request_headers_len].name = strtok(arg, ":");
        arguments->headers[request_headers_len].value = strtok(NULL, "");
        request_headers_len++;

        break;

    case 'R':
        if (response_headers_len == RSC_HEADERS_MAX_LEN)
            argp_error(state, "Too many HTTP Response Headers (%d -R).",
                RSC_HEADERS_MAX_LEN + 1);

        arguments->response.headers[response_headers_len].name = strtok(
            arg, ":");
        arguments->response.headers[response_headers_len].value = strtok(
            NULL, "");
        response_headers_len++;

        break;

    case ARGP_KEY_ARG:
        switch (state->arg_num) {
        case 0: strcpy(arguments->tcp.iface, arg); break;
        case 1: strcpy(arguments->tcp.real_server, arg); break;
        case 2: strcpy(arguments->tcp.virtual_ip, arg); break;
        case 3: arguments->tcp.port = (uint16_t)atoi(arg); break;
        case 4: strcpy(arguments->host, arg); break;
        case 5: strcpy(arguments->path, arg); break;
        default: argp_usage(state); break;
        }
        break;

    case ARGP_KEY_END:
        if (state->arg_num < CHECK_HTTP_GET_RAW_ARGS)
            argp_usage(state);
        break;

    default: return ARGP_ERR_UNKNOWN; break;
    }

    return 0;
}

/* Argp parser */
static struct argp argp = { options, parse_opt, args_doc, doc };

/*
 * Parse command line arguments
 */
check_http_raw_arguments_type
parse_args(int argc, char **argv)
{
    check_http_raw_arguments_type arguments = {{0}};

    /* Default values. */
    arguments.tcp.verbosity = RSC_NO_VERBOSITY;
    arguments.tcp.timeout = 1000;  /* 1s, unit is ms */
    strcpy(arguments.method, "GET");

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    return arguments;
}
