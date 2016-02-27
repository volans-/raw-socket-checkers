/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        check_tcp_raw header file.
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

#ifndef _RSC_CHECK_TCP_RAW_HEADER
# define _RSC_CHECK_TCP_RAW_HEADER 1

/*
 * Parse command line arguments
 */
check_tcp_raw_arguments_type parse_args(int argc, char **argv);

/*
 * Perform a TCP check based on the load balancer role
 */
void tcp_check(check_tcp_raw_arguments_type *);

#endif
