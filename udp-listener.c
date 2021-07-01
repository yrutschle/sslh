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


/* UDP support types and stuff */
struct known_udp_source {
    int allocated;
    struct sockaddr client_addr; /* Contains the remote client address */
    socklen_t addrlen;

    int local_endpoint; /* Contains the local address */

    time_t last_active;

    struct sslhcfg_protocols_item* proto; /* Where to connect it to */
    /* We need one local socket for each target server, so we know where to
     * forward server responses */
    int target_sock;  
};


/* Find if the specified source has been seen before. -1 if not found
 *
 * TODO This is linear search and needs to be changed to something better for
 * production if we have more than a dozen sources
 * Also, this assumes src_addr from recvfrom() are repeatable for a specific
 * source...
 * */
static int known_source(struct known_udp_source* ks, int ks_len, struct sockaddr* addr, socklen_t addrlen)
{
    int i;

    for (i = 0; i < ks_len; i++) {
        if (ks[i].allocated) {
            if (!memcmp(&ks[i].client_addr, addr, addrlen)) {
                return i;
            }
        }
    }
    return -1;
}

static int get_empty_source(struct known_udp_source* ks, int ks_len)
{
    int i;
    for (i = 0; i < ks_len; i++)
        if (!ks[i].allocated) return i;
    return -1;
}

/* TODO: Make that dynamic... */
#define MAX_UDP_SRC 1024
/* Array to keep the UDP sources we have seen before */
struct known_udp_source udp_known_sources[MAX_UDP_SRC];

/* Process UDP coming from outside (client towards server)
 * If it's a new source, probe; otherwise, forward to previous target 
 * Returns: >= 0 sockfd of newly allocated socket, for new connections
 * -1 otherwise
 * */
int udp_c2s_forward(int sockfd, cnx_collection* collection)
{
    char addr_str[NI_MAXHOST+1+NI_MAXSERV+1];
    struct sockaddr src_addr;
    struct addrinfo addrinfo;
    struct known_udp_source* src;
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
    target = known_source(udp_known_sources, ARRAY_SIZE(udp_known_sources), 
                          &src_addr, addrlen);
    addrinfo.ai_addr = &src_addr;
    addrinfo.ai_addrlen = addrlen;
    if (cfg.verbose) 
        fprintf(stderr, "received %ld UDP from %d:%s\n", len, target, sprintaddr(addr_str, sizeof(addr_str), &addrinfo));

    if (target == -1) {
        target = get_empty_source(udp_known_sources, ARRAY_SIZE(udp_known_sources));
        fprintf(stderr, "source target index %d\n", target);
        if (target == -1) {
            fprintf(stderr, "Out of UDP structs\n");
            exit(0); /* TODO handle this properly */
        }

        /* save this as an active connection */
        src = &udp_known_sources[target];
        src->allocated = 1;
        src->client_addr = src_addr;
        src->addrlen = addrlen;
        src->local_endpoint = sockfd;

        res = probe_buffer(data, len, &src->proto);
        /* First version: if we can't work out the protocol from the first
         * packet, drop it. Conceivably, we could store several packets to
         * run probes on packet sets */
        if (cfg.verbose) fprintf(stderr, "UDP probed: %d\n", res);
        if (res != PROBE_MATCH) {
            src->allocated = 0;
            return -1;
        }

        src->target_sock = socket(src->proto->saddr->ai_family, SOCK_DGRAM, 0);
        out = src->target_sock;

        struct connection* cnx = collection_alloc_cnx_from_fd(collection, out);
        cnx->type = SOCK_DGRAM;
        cnx->udp_source = &udp_known_sources[target];
    }

    src = &udp_known_sources[target];

    /* at this point src is the UDP connection */
    res = sendto(src->target_sock, data, len, 0, 
                 src->proto->saddr->ai_addr, src->proto->saddr->ai_addrlen);
    src->last_active = time(NULL);
    fprintf(stderr, "sending %d to %s\n", 
            res, sprintaddr(data, sizeof(data), src->proto->saddr));
    return out;
}


void udp_s2c_forward(struct known_udp_source* src)
{
    int sockfd = src->target_sock;
    char data[65536];
    int res;

    res = recvfrom(sockfd, data, sizeof(data), 0, NULL, NULL);
    fprintf(stderr, "recvfrom %d\n", res);
    CHECK_RES_DIE(res, "udp_listener/recvfrom");
    res = sendto(src->local_endpoint, data, res, 0,
                 &src->client_addr, src->addrlen);
    src->last_active = time(NULL);
    fprintf(stderr, "sendto %d to\n", res);
}


/* Clears old connections from udp_known_sources, and from passed fd_set */
#define UDP_TIMEOUT 60   /* Timeout before forgetting the connection, in seconds */
int udp_timedout(struct connection* cnx)
{
    int i;
    time_t now = time(NULL);
    struct known_udp_source* src = cnx->udp_source;

    if (!cnx->udp_source) return 0; /* Not a UDP connection */

    if (src->allocated && (now - src->last_active > UDP_TIMEOUT)) {
        close(src->target_sock);
        memset(src, 0, sizeof(*src));
        if (cfg.verbose > 3) 
            fprintf(stderr, "disconnect timed out UDP %d\n", i);
        return 1;
    }
    return 0;
}

