/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        Simple RAW HTTP GET check, a raw socket version of the
                Keepalived's HTTP_GET check.
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
#include "check_http_get_raw.h"

/*
Usage: check_http_get_raw [OPTION...]
            SOURCE_IFACE REAL_SERVER VIRTUAL_IP PORT HOST PATH VALUE

check_http_get_raw -- an HTTP GET checker with RAW sockets

It performs an HTTP GET of PATH for HOST using a RAW socket sending the packets
from the SOURCE_INTERFACE to the MAC address of the REAL_SERVER with a TCP/IP
destination set to VIRTUAL_IP and PORT. The MD5 hash of the HTTP response body
is then compared to VALUE for the check to be successful.

This is suitable to be used as a check for load balancers in direct routing
mode (LVS-DR) to ensure that the real server is indeed answering to packets
with the VIRTUAL_IP destination IP.

Example:
check_http_get_raw -vvvv -t 500 -r /var/run/lvs.role eth0 10.0.0.42 10.0.0.100
80 www.example.com /healthcheck d36f8f9425c4a8000ad9c4a97185aca5

Example to calculate the MD5 of the HTTP response:
curl -s -H "Host: www.example.com" http://10.0.0.42/healthcheck | md5sum

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

  HOST            Virtual host to made the request to, becomes the HTTP Host
                  header in the request (i.e. www.example.com)
  PATH            HTTP Resource to request, with leading slash
                  (i.e. /healthcheck)
  VALUE           MD5 hash of the HTTP response body to verify it
                  (i.e. d36f8f9425c4a8000ad9c4a97185aca5)

============================
OPTIONS
----------------------------

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
                             -v)    CLI parameters and HTTP response summary
                             -vv)   Print also the full HTTP response body
                             -vvv)  Print also all TCP packets
                             -vvvv) Print also all ARP packets
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
 */
int
main(int argc, char **argv)
{
    uint8_t ret;

    check_http_get_raw_arguments_type arguments = parse_args(argc, argv);

    /* Set global verbosity */
    (void)check_verbosity(RSC_NO_VERBOSITY, arguments.tcp.verbosity);

    rsc_log(RSC_HL_LOW, stdout,
        "[PARAMS] iface: %s, real_server: %s, virtual_ip: %s, "
        "port: %d, host: %s, path: %s, value: %s, role_file: %s, "
        "timeout: %dms, verbosity: %u\n",
        arguments.tcp.iface, arguments.tcp.real_server,
        arguments.tcp.virtual_ip, arguments.tcp.port, arguments.host,
        arguments.path, arguments.value, arguments.tcp.role_file,
        arguments.tcp.timeout, arguments.tcp.verbosity);

    ret = http_get_check(&arguments);

    if (ret == 0)
        exit(EXIT_SUCCESS);
    else
        exit(EXIT_FAILURE);
}
