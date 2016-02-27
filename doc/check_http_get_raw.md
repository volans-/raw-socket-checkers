# Check HTTP GET RAW (_BETA_)

It performs an _HTTP GET_ of __PATH__ for __HOST__ using a RAW socket sending
the packets from the __SOURCE_INTERFACE__ to the _MAC address_ of the
__REAL_SERVER__ with a TCP/IP destination set to __VIRTUAL_IP__ and
__PORT__. The _MD5 hash_ of the HTTP response body is then compared to
__VALUE__ for the check to be successful.

This is suitable to be used as a check for load balancers in direct routing
mode (_LVS-DR_) to ensure that the real server is indeed answering to packets
with the __VIRTUAL_IP__ destination IP.

It is basically the same check as *HTTP_GET* in _Keepalived_.

__N.B.__: This check accepts only single TCP packets replies, see the _TODO_
section in the [project README](../README.md) for future developments.

## Dependencies

* GNU C compiler (i.e. _gcc_ package).
* GNU C Library: Development Libraries and Header Files (i.e. install
  _libc6-dev_ package (or equivalent) on Debian based distros, _glibc-devel_ on
  RedHat based ones).
* OpenSSL development files (i.e. install _libssl-dev_ package on Debian based
  distros, _openssl-devel_ on RedHat based ones).

## Compilation

```sh
make http_get
```

The binary `check_http_get_raw` is created in the `bin/` directory.

## Usage

Because of the usage of _RAW_ sockets, the check need to be run as _root_.

```sh
check_http_get_raw [OPTION...]
    SOURCE_IFACE
    REAL_SERVER
    VIRTUAL_IP
    PORT
    HOST
    PATH
    VALUE
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
* __HOST__: HTTP Host header to be used (i.e. _www.example.com_).
* __PATH__: HTTP Resource to request, with leading slash (i.e. _/healthcheck_)
* __VALUE__: _MD5 hash_ of the HTTP response body to verify it (i.e.
  _d36f8f9425c4a8000ad9c4a97185aca5_)

### Options

* __-r__, __--role-file=FILE__: Path of the file that contains the current role
  of the load balancer. Only the first character is read, accepted values are:
  _1 => MASTER_, _anything else => BACKUP_. When this parameter is set the
  checks on a BACKUP server are done using the real server IP instead of the
  VIRTUAL_IP with a standard _TCP_ socket.
* __-t__, __--timeout=MILLISECONDS__: Timeout for each REAL_SERVER reply in ms.
  To disable set to 0. [Default: 1000]
* __-v__, __--verbose__: Produce increasing verbose output to standard error
  based on the number of occurrences. `-v`: CLI parameters and HTTP response
  summary. `-vv`: Print also the full HTTP response body. `-vvv`: Print also
  all TCP packets. `-vvvv`: Print also all ARP packets.
* __-?__, __--help__: Give this help list
* __--usage__: Give a short usage message

### Sample usage

To calculate the _MD5_ of the expected HTTP response body:
```sh
curl -s -H "Host: www.example.com" http://10.0.0.42/healthcheck | md5sum
```

Use the resulting hash as last parameter for *check_http_get_raw*:
```sh
check_http_get_raw -vv -t 500 -r /var/run/lvs.role eth0 10.0.0.42 10.0.0.100 80 www.example.com /healthcheck d36f8f9425c4a8000ad9c4a97185aca5
```
The sample usage and sample output uses a verbosity level of 2 to show only
HTTP related logging, see the sample output of the
[TCP check](check_tcp_raw.md) for an example of TCP and ARP
logging.

### Sample output

```
[PARAMS] iface: eth0, real_server: 10.0.0.42, virtual_ip: 10.0.0.100, port: 80, host: www.example.com, path: /healthcheck, value: d36f8f9425c4a8000ad9c4a97185aca5, role_file: /var/run/lvs.role, timeout: 500ms, verbosity: 2
* Connected to 10.0.0.100 (22:22:22:22:22:22) port 80
> GET /healthcheck HTTP/1.1
> User-Agent: raw-socket-checkers/1.0
> Host: www.example.com
>
< HTTP/1.1 200 OK
< Server: nginx/1.6.2
< Date: Fri, 08 Jan 2016 11:08:20 GMT
< Content-Type: text/plain
< Content-Length: 3
< Last-Modified: Fri, 08 Jan 2016 11:03:22 GMT
< Connection: keep-alive
< ETag: "568f977a-3"
< Accept-Ranges: bytes
<
OK
* HTTP Body MD5 is d36f8f9425c4a8000ad9c4a97185aca5
* Closed connection to 10.0.0.100
```

### Full help message

```
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
```
