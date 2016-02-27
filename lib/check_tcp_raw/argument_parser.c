/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        CLI argument parser for the check_tcp_raw check.
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

#define CHECK_TCP_RAW_ARGS 4  /* Number of mandatory arguments */

/* Program documentation */
static char doc[] = "\ncheck_tcp_raw -- a TCP/IPv4 checker with RAW "
    "sockets\n\n"
    "Performs a TCP check (SYN - SYN/ACK - ACK - RST/ACK) using a RAW socket"
    ", sending the packets from the SOURCE_INTERFACE to the MAC address of "
    "the REAL_SERVER with the TCP/IP destination set to the VIRTUAL_IP "
    "and PORT.\n\n"
    "This is suitable to be used as a check for load balancers in direct "
    "routing mode (LVS-DR) to ensure that the real server is indeed answering "
    "to packets with the VIRTUAL_IP destination IP.\n\n"
    "Example:\ncheck_tcp_raw -vv -t 500 -r /var/run/lvs.role eth0 10.0.0.42 "
    "10.0.0.100 80\n\n"
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
    "============================\nOPTIONS\n----------------------------\n";

/* Mandatory arguments */
static char args_doc[] = "SOURCE_IFACE REAL_SERVER VIRTUAL_IP PORT";

/* Available options */
static struct argp_option options[] = {
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
        "-v)  CLI parameters and all TCP packets\n"
        "-vv) Print also all ARP packets"
    },
    { 0 }
};

/*
 * Parse a single option
 */
static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    /* The input argument from argp_parse is a pointer to our structure. */
    check_tcp_raw_arguments_type *arguments = state->input;

    switch (key) {
    case 'v': arguments->verbosity++; break;
    case 't': arguments->timeout = (uint32_t) atoi(arg); break;
    case 'r': strcpy(arguments->role_file, arg); break;

    case ARGP_KEY_ARG:
        switch (state->arg_num) {
        case 0: strcpy(arguments->iface, arg); break;
        case 1: strcpy(arguments->real_server, arg); break;
        case 2: strcpy(arguments->virtual_ip, arg); break;
        case 3: arguments->port = (uint16_t)atoi(arg); break;
        default: argp_usage(state); break;
        }
        break;

    case ARGP_KEY_END:
        if (state->arg_num < CHECK_TCP_RAW_ARGS)
            argp_usage(state);
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/* Argp parser */
static struct argp argp = { options, parse_opt, args_doc, doc };

/*
 * Parse command line arguments
 */
check_tcp_raw_arguments_type
parse_args(int argc, char **argv)
{
    check_tcp_raw_arguments_type arguments = {0};

    /* Default values. */
    arguments.verbosity = RSC_HL_HIGH;  /* Lower layers no verbosity */
    arguments.timeout = 1000;  /* 1s, unit is in ms */

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    return arguments;
}
