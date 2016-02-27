# Check TCP RAW

A TCP/IPv4 RAW checker. Performs a TCP check (_SYN_ - _SYN/ACK_ - _ACK_ -
_RST/ACK_) using a RAW socket, sending the packets from the
__SOURCE_INTERFACE__ to the _MAC address_ of the __REAL_SERVER__ with the
TCP/IP destination set to the __VIRTUAL_IP__ and __PORT__.

This is suitable to be used as a check for load balancers in direct routing
mode (_LVS-DR_) to ensure that the real server is indeed answering to packets
with the __VIRTUAL_IP__ destination IP.

It is basically the same check as *TCP_CHECK* in _Keepalived_. Optionally a
clean close can be performed (FIN/ACK - FIN/ACK - ACK) instead of the quick
close (RST/ACK).

## Dependencies

* C compiler (i.e. _GCC_).
* GNU C Library: Development Libraries and Header Files (i.e. install
  _libc6-dev_ package (or equivalent) on Debian based distros, _glibc-devel_ on
  RedHat based ones).

## Compilation

```sh
make tcp
```

The binary `check_tcp_raw` is created in the `bin/` directory.

## Usage

```sh
check_tcp_raw [OPTION...] SOURCE_IFACE REAL_SERVER VIRTUAL_IP PORT
```

### Exit status

*EXIT_SUCCESS* on success, *EXIT_FAILURE* on failure, as defined in _stdlib.h_.

### Parameters

* __SOURCE_IFACE__: the name of the network interface to use to send the
  packets from (i.e. _eth0_).
* __REAL_SERVER__: IPv4 or hostname of the real server to check. Only used to
  get it's MAC address (i.e. _10.0.0.42_).
* __VIRTUAL_IP__: IPv4 or hostname of the virtual IP for which the check
  should be performed, used as destination IP in the TCP packets
  (i.e. _10.0.0.100_).
* __PORT__: TCP port number to use for the check (i.e. _80_).

### Options

* __-c__, __--clean-close__: Close the connection in a clean way (FIN/ACK -
  FIN/ACK - ACK) instead of sending an RST/ACK. Some software don't like to
  have the connection closed abruptly with an RST and might flood their logs.
* __-r__, __--role-file=FILE__: Path of the file that contains the current role
  of the load balancer. Only the first character is read, accepted values are:
  _1 => MASTER_, _anything else => BACKUP_. When this parameter is set the
  checks on a BACKUP server are done using the real server IP instead of the
  VIRTUAL_IP with a standard _TCP_ socket.
* __-t__, __--timeout=MILLISECONDS__: Timeout for each REAL_SERVER reply in ms.
  To disable set to 0. [Default: 1000]
* __-v__, __--verbose__: Produce increasing verbose output to standard error
  based on the number of occurrences. `-v`: CLI parameters and all TCP packets.
  `-vv`: print also all ARP packets.
* __-?__, __--help__: Give this help list
* __--usage__: Give a short usage message

### Sample usage

```sh
check_tcp_raw -vv -t 500 -r /var/run/lvs.role eth0 10.0.0.42 10.0.0.100 80
```

### Sample output

```
# check_tcp_raw -vv -t 500 -r /var/run/lvs.role eth0 10.0.0.42 10.0.0.100 80
[PARAMS] iface: eth0, real_server: 10.0.0.42, virtual_ip: 10.0.0.100, port: 80, role_file: /var/run/lvs.role, timeout: 500ms, verbosity: 2
(11:11:11:11:11:11) 10.0.0.21 ARP request who has 10.0.0.42 (ff:ff:ff:ff:ff:ff)
(22:22:22:22:22:22) 10.0.0.42 ARP reply to 10.0.0.21 (11:11:11:11:11:11)
(11:11:11:11:11:11) 10.0.0.21:54321 > 10.0.0.100:80 (22:22:22:22:22:22) Flags [S], seq 123456789, ack 0
(22:22:22:22:22:22) 10.0.0.100:80 > 10.0.0.21:54321 (11:11:11:11:11:11) Flags [S.], seq 987654321, ack 123456790
(11:11:11:11:11:11) 10.0.0.21:54321 > 10.0.0.100:80 (22:22:22:22:22:22) Flags [.], seq 123456790, ack 987654321
(11:11:11:11:11:11) 10.0.0.21:54321 > 10.0.0.100:80 (22:22:22:22:22:22) Flags [R.], seq 123456790, ack 2772578388
```

### Full help message

```
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
```
