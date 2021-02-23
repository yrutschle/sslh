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


/* UDP support types and stuff */
struct known_udp_source {
    int allocated;
    struct sockaddr sockaddr;
    socklen_t addrlen;
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
            if (!memcmp(&ks[i].sockaddr, addr, addrlen)) {
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


/* Process UDP coming from outside:
 * If it's a new source, probe; otherwise, forward to previous target 
 * Returns: >= 0 sockfd of newly allocated socket, for new connections
 * -1 otherwise
 * */
static int udp_extern_forward(int sockfd) {
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

    fprintf(stderr, "recvfrom(%d)\n", getpid());
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
        if (target == -1) exit(0); /* TODO handle this properly */
        /* A probe worked: save this as an active connection */
        src = &udp_known_sources[target];
        src->allocated = 1;
        src->sockaddr = src_addr;
        src->addrlen = addrlen;
        src->last_active = time(NULL);

        res = probe_buffer(data, len, &src->proto);
        /* First version: if we can't work out the protocol from the first
         * packet, drop it. Conceivably, we could store several packets to
         * run probes on packet sets */
        if (cfg.verbose) fprintf(stderr, "UDP probed: %d\n", res);
        if (res != PROBE_MATCH) return -1;

        src->target_sock = socket(src->proto->saddr->ai_family, SOCK_DGRAM, 0);
        out = src->target_sock;
    }

    src = &udp_known_sources[target];
    /* at this point src is the UDP connection */
    res = sendto(src->target_sock, data, len, 0, 
                 src->proto->saddr->ai_addr, src->proto->saddr->ai_addrlen);
    src->last_active = time(NULL);
    fprintf(stderr, "sending %d to %s", 
            res, sprintaddr(data, sizeof(data), src->proto->saddr));
    return out;
}


/* Clears old connections from udp_known_sources, and from passed fd_set */
#define UDP_TIMEOUT 60   /* Timeout before forgetting the connection, in seconds */
static void reap_timeouts(struct known_udp_source* sources, int n_src, fd_set* fd)
{
    int i;
    time_t now = time(NULL);
    struct known_udp_source* src;

    for (i = 0; i < n_src; i++) {
        src = &sources[i];
        if (src->allocated && (now - src->last_active > UDP_TIMEOUT)) {
            close(src->target_sock);
            FD_CLR(src->target_sock, fd);
            memset(&sources[i], 0, sizeof(sources[i]));
            if (cfg.verbose > 3) 
                fprintf(stderr, "disconnect %d\n", i);
        }
    }
}


/* UDP listener: upon incoming packet, find where it should go
 * This is run in its own process and never returns.
 */
void udp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint)
{
    fd_set fds_r, fds_r_tmp;
    char data[65536]; /* TODO what? */
    int max_fd, res, sockfd, i;
    struct known_udp_source* src;
    struct timeval tv;

    FD_ZERO(&fds_r);
    FD_SET(endpoint[active_endpoint].socketfd, &fds_r);
    max_fd = endpoint[active_endpoint].socketfd + 1;

    while (1) {
        fds_r_tmp = fds_r;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        res = select(max_fd + 1,  &fds_r_tmp, NULL, NULL, &tv);
        CHECK_RES_DIE(res, "select");

        if (res) {
            if (FD_ISSET(endpoint[active_endpoint].socketfd, &fds_r_tmp)) {
                sockfd = udp_extern_forward(endpoint[active_endpoint].socketfd);
                if (sockfd >= 0) {
                    FD_SET(sockfd, &fds_r);
                    max_fd = MAX(max_fd, sockfd);
                }
            } else {
                for (i = 0; i < ARRAY_SIZE(udp_known_sources); i++) {
                    src = &udp_known_sources[i];
                    if (src->allocated) {
                        sockfd = src->target_sock;
                        if (FD_ISSET(sockfd, &fds_r_tmp)) {
                            res = recvfrom(sockfd, data, sizeof(data), 0, NULL, NULL);
                            fprintf(stderr, "recvfrom %d\n", res);
                            CHECK_RES_DIE(res, "udp_listener/recvfrom");
                            res = sendto(endpoint[active_endpoint].socketfd, data, res, 0,
                                         &src->sockaddr, src->addrlen);
                            src->last_active = time(NULL);
                            fprintf(stderr, "sendto %d to\n", res);
                        }
                    }
                }
            }
        }
        reap_timeouts(udp_known_sources, ARRAY_SIZE(udp_known_sources), &fds_r);
    }
}
