###############################################################################
# Software:    raw-socket-checkers is a collection of network checks suitable
#              to be used as a check for load balancers in direct routing
#              mode (LVS-DR) to ensure that the real server is indeed
#              answering to packets with the VIRTUAL_IP destination IP, see
#              <https://github.com/volans-/raw-socket-checkers>
#
# Part:        Makefile.
#
# Author:      Riccardo Coccioli, <volans-@users.noreply.github.com>
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#              See the GNU General Public License for more details:
#              <http://www.gnu.org/licenses/>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU General Public License
#              as published by the Free Software Foundation; either version
#              2 of the License or (at your option) any later version.
#
# Copyright (C) 2016 Riccardo Coccioli, <volans-@users.noreply.github.com>
###############################################################################

CC = gcc
CFLAGS = -Wall
HTTP_LIBS = -lcrypto

HEADERS = $(wildcard include/*.h)

SRC_COMMON = lib/common.c lib/tcp.c
SRC_TCP = $(SRC_COMMON) $(wildcard lib/check_tcp_raw/*.c)
SRC_HTTP_GET = $(SRC_COMMON) lib/http.c $(wildcard lib/check_http_get_raw/*.c)
SRC_HTTP = $(SRC_COMMON) lib/http.c $(wildcard lib/check_http_raw/*.c)

OBJ_TCP = $(patsubst lib/%.c, build/%.o, $(SRC_TCP))
OBJ_HTTP_GET = $(patsubst lib/%.c, build/%.o, $(SRC_HTTP_GET))
OBJ_HTTP = $(patsubst lib/%.c, build/%.o, $(SRC_HTTP))

.PHONY: default all clean folders tcp http_get http

default: all
all: tcp http_get http

folders:
	@mkdir -p bin build/check_tcp_raw build/check_http_get_raw build/check_http_raw

build/%.o: lib/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@ -Iinclude/

bin/check_tcp_raw: $(OBJ_TCP) src/check_tcp_raw.c
	$(CC) -Wall -o $@ $(OBJ_TCP) src/check_tcp_raw.c -Iinclude/
tcp: folders bin/check_tcp_raw

bin/check_http_get_raw: $(OBJ_HTTP_GET) src/check_http_get_raw.c
	$(CC) -Wall -o $@ $(OBJ_HTTP_GET) src/check_http_get_raw.c -Iinclude/ $(HTTP_LIBS)
http_get: folders bin/check_http_get_raw

bin/check_http_raw: $(OBJ_HTTP) src/check_http_raw.c
	$(CC) -Wall -o $@ $(OBJ_HTTP) src/check_http_raw.c -Iinclude/ $(HTTP_LIBS)
http: folders bin/check_http_raw

clean:
	@rm -rf build/ bin/ check_tcp_raw
