/*
# proxyprotocol: Support for HAProxy's proxyprotocol
#
# Copyright (C) 2025  Yves Rutschle
# 
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more
# details.
# 
# The full text for the General Public License is here:
# http://www.gnu.org/licenses/gpl.html

*/

#include <proxy_protocol.h>
#include "common.h"
#include "log.h"


/* Converts socket family to libproxyprotocol family */
static int family_to_pp(int af_family)
{
    switch (af_family) {
    case AF_INET:
        return ADDR_FAMILY_INET;

    case AF_INET6:
        return ADDR_FAMILY_INET6;

    case AF_UNIX:
        return ADDR_FAMILY_UNIX;

    default:
        print_message(msg_int_error, "Unknown internal socket family %d\n", af_family);
        return -1;
    }
}

int pp_write_header(int pp_version, struct connection* cnx)
{
    pp_info_t pp_info_in_v1 = {
        .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
    };
    uint16_t pp1_hdr_len;
    int32_t error;

    struct sockaddr_storage ss;
    struct addrinfo addr;
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    int res;

    addr.ai_addr = (struct sockaddr*)&ss;
    addr.ai_addrlen = sizeof(ss);

    res = getpeername(cnx->q[0].fd, addr.ai_addr, &addr.ai_addrlen);
    res = getnameinfo(addr.ai_addr, addr.ai_addrlen,
                      host, sizeof(host),
                      serv, sizeof(serv),
                      NI_NUMERICHOST | NI_NUMERICSERV );
    memcpy(pp_info_in_v1.src_addr, host, sizeof(pp_info_in_v1.src_addr));
    pp_info_in_v1.src_port = atoi(serv);
    pp_info_in_v1.address_family = family_to_pp(addr.ai_addr->sa_family);

    res = getpeername(cnx->q[1].fd, addr.ai_addr, &addr.ai_addrlen);
    res = getnameinfo(addr.ai_addr, addr.ai_addrlen,
                      host, sizeof(host),
                      serv, sizeof(serv),
                      NI_NUMERICHOST | NI_NUMERICSERV );
    memcpy(pp_info_in_v1.dst_addr, host, sizeof(pp_info_in_v1.dst_addr));
    pp_info_in_v1.dst_port = atoi(serv);

    uint8_t *pp1_hdr = pp_create_hdr(pp_version, &pp_info_in_v1, &pp1_hdr_len, &error);

    if (!pp1_hdr) {
        print_message(msg_system_error, "pp_create_hrd:%d:%s\n", error, pp_strerror(error));
        return -1;
    }
    defer_write_before(&cnx->q[1], pp1_hdr, pp1_hdr_len);

    pp_info_clear(&pp_info_in_v1);
    free(pp1_hdr);

    return 0;
}
