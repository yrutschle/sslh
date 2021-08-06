/*
   udp-listener.c: handles demultplexing UDP protocols

# Copyright (C) 2020-2021  Yves Rutschle
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

#include "common.h"
#include "probe.h"
#include "sslh-conf.h"
#include "udp-listener.h"


/* Find if the specified source has been seen before. -1 if not found
 *
 * TODO This is linear search and needs to be changed to something better for
 * production if we have more than a dozen sources
 * Also, this assumes src_addr from recvfrom() are repeatable for a specific
 * source...
 * */
static int known_source(cnx_collection* collection, int max_fd, struct sockaddr* addr, socklen_t addrlen)
{
    int i;

    for (i = 0; i < max_fd; i++) {
        struct connection* cnx = collection_get_cnx_from_fd(collection, i);
        if (cnx && (cnx->type == SOCK_DGRAM) && cnx->target_sock) {
            if (!memcmp(&cnx->client_addr, addr, addrlen)) {
                return i;
            }
        }
    }
    return -1;
}

/* Process UDP coming from outside (client towards server)
 * If it's a new source, probe; otherwise, forward to previous target 
 * Returns: >= 0 sockfd of newly allocated socket, for new connections
 * -1 otherwise
 * */
int udp_c2s_forward(int sockfd, cnx_collection* collection, int max_fd)
{
    char addr_str[NI_MAXHOST+1+NI_MAXSERV+1];
    struct sockaddr src_addr;
    struct addrinfo addrinfo;
    struct sslhcfg_protocols_item* proto;
    struct connection* cnx;
    ssize_t len;
    socklen_t addrlen;
    int res, target, out = -1;
    char data[65536]; /* Theoritical max is 65507 (https://en.wikipedia.org/wiki/User_Datagram_Protocol).
                         This will do.  Dynamic allocation is possible with the MSG_PEEK flag in recvfrom(2), but that'd imply
                         malloc/free overhead for each packet, when really 64K is not that much */

    addrlen = sizeof(src_addr);
    len = recvfrom(sockfd, data, sizeof(data), 0, &src_addr, &addrlen);
    if (len < 0) {
        perror("recvfrom");
        return -1;
    }
    target = known_source(collection, max_fd, &src_addr, addrlen);
    addrinfo.ai_addr = &src_addr;
    addrinfo.ai_addrlen = addrlen;
    if (cfg.verbose) 
        fprintf(stderr, "received %ld UDP from %d:%s\n", len, target, sprintaddr(addr_str, sizeof(addr_str), &addrinfo));

    if (target == -1) {
        res = probe_buffer(data, len, &proto);
        /* First version: if we can't work out the protocol from the first
         * packet, drop it. Conceivably, we could store several packets to
         * run probes on packet sets */
        if (cfg.verbose) fprintf(stderr, "UDP probed: %d\n", res);
        if (res != PROBE_MATCH) {
            return -1;
        }

        out = socket(proto->saddr->ai_family, SOCK_DGRAM, 0);
        struct connection* cnx = collection_alloc_cnx_from_fd(collection, out);
        if (!cnx) return -1;
        target = out;
        cnx->target_sock = out;
        cnx->proto = proto;
        cnx->type = SOCK_DGRAM;
        cnx->client_addr = src_addr;
        cnx->addrlen = addrlen;
        cnx->local_endpoint = sockfd;
    }
    cnx = collection_get_cnx_from_fd(collection, target);

    /* at this point src is the UDP connection */
    res = sendto(cnx->target_sock, data, len, 0,
                 cnx->proto->saddr->ai_addr, cnx->proto->saddr->ai_addrlen);
    cnx->last_active = time(NULL);
    fprintf(stderr, "sending %d to %s\n", 
            res, sprintaddr(data, sizeof(data), cnx->proto->saddr));
    return out;
}


void udp_s2c_forward(struct connection* cnx)
{
    int sockfd = cnx->target_sock;
    char data[65536];
    int res;

    res = recvfrom(sockfd, data, sizeof(data), 0, NULL, NULL);
    fprintf(stderr, "recvfrom %d\n", res);
    CHECK_RES_DIE(res, "udp_listener/recvfrom");
    res = sendto(cnx->local_endpoint, data, res, 0,
                 &cnx->client_addr, cnx->addrlen);
    cnx->last_active = time(NULL);
    fprintf(stderr, "sendto %d to\n", res);
}


/* returns date at which this socket times out. */
int udp_timeout(struct connection* cnx)
{
    if (cnx->type != SOCK_DGRAM) return 0; /* Not a UDP connection */

    return cnx->proto->udp_timeout + cnx->last_active;
}

