/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        Simple RAW TCP check, a raw socket version of the
                Keepalived's TCP_CHECK check.
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

#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "check_tcp_raw.h"

/*
Usage: check_tcp_raw [OPTION...] SOURCE_IFACE REAL_SERVER VIRTUAL_IP PORT

check_tcp_raw -- a TCP/IPv4 checker with RAW sockets

Performs a TCP check (SYN - SYN/ACK - ACK - RST/ACK) using a RAW socket,
sending the packets from the SOURCE_INTERFACE to the MAC address of the
REAL_SERVER with the TCP/IP destination set to the VIRTUAL_IP and PORT.

This is suitable to be used as a check for load balancers in direct routing
mode (LVS-DR) to ensure that the real server is indeed answering to packets
with the VIRTUAL_IP destination IP.

Optionally a clean close can be performed (FIN/ACK - FIN/ACK - ACK) instead of
the quick close (RST/ACK).

Example:
check_tcp_raw -vv -t 500 -r /var/run/lvs.role eth0 10.0.0.42 10.0.0.100 80

============================
EXIT STATUS
----------------------------

EXIT_SUCCESS on success, EXIT_FAILURE on failure.

============================
PARAMETERS
----------------------------

  SOURCE_IFACE    the name of the network interface to use to send the packets
                  from (i.e. eth0).

  REAL_SERVER     IPv4 or hostname of the real server to check. Only used to
                  get it's MAC address (i.e. 10.0.0.42).

  VIRTUAL_IP      IPv4 or hostname of the virtual IP for which the check
                  should be performed, used as destination IP in the TCP
                  packets (i.e. 10.0.0.100)

  PORT            TCP port number to use for the check (i.e. 80)

============================
OPTIONS
----------------------------

  -c, --clean-close          Close the connection in a clean way (FIN/ACK -
                             FIN/ACK - ACK) instead of sending an RST/ACK. Some
                             software don't like to have the connection closed
                             abruptly with an RST and might flood their logs.
  -r, --role-file=FILE       Path of the file that contains the current role of
                             the load balancer. Only the first character is
                             read, accepted values are: 1 => MASTER, anything
                             else => BACKUP. When this parameter is set the
                             checks on a BACKUP server are done using the real
                             server IP instead of the VIRTUAL_IP with a
                             standard TCP socket.
  -t, --timeout=MILLISECONDS Timeout for each REAL_SERVER reply in ms.
                             To disable set to 0. [Default: 1000]
  -v, --verbose              Produce increasing verbose output to standard
                             error based on the number of occurrences:
                             -v)  CLI parameters and all TCP packets
                             -vv) Print also all ARP packets
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
*/
int
main(int argc, char **argv)
{
    check_tcp_raw_arguments_type arguments = parse_args(argc, argv);

    /* Set global verbosity */
    (void)check_verbosity(RSC_NO_VERBOSITY, arguments.verbosity);

    rsc_log(RSC_LL_LOW, stdout,
        "[PARAMS] iface: %s, real_server: %s, virtual_ip: %s, "
        "port: %d, role_file: %s, timeout: %dms, verbosity: %u\n",
        arguments.iface, arguments.real_server, arguments.virtual_ip,
        arguments.port, arguments.role_file, arguments.timeout,
        (arguments.verbosity - RSC_HL_HIGH));

    tcp_check(&arguments);

    exit(EXIT_SUCCESS);
}
