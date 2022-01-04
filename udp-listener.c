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

#include <limits.h>

#include "common.h"
#include "probe.h"
#include "sslh-conf.h"
#include "udp-listener.h"


/* returns date at which this socket times out. */
static int udp_timeout(struct connection* cnx)
{
    if (cnx->type != SOCK_DGRAM) return 0; /* Not a UDP connection */

    return cnx->proto->udp_timeout + cnx->last_active;
}

/* Check all connections to see if a UDP connections has timed out, then free
 * it. At the same time, keep track of the closest, next timeout. Only do the
 * search through connections if that timeout actually happened. If the
 * connection that would have timed out has had activity, it doesn't matter: we
 * go through connections to find the next timeout, which was needed anyway. 
 *
 * This gets called every time a UDP packet is received from the outside, i.e.
 * every time we might need to free up resources. If no packets come in, we
 * don't time out anything, as we don't need the resources.
 *
 * TODO: use a better algorithm to avoid going through all connections each
 * time.
 *
 * */
void udp_timeouts(struct loop_info* fd_info)
{
    int i;
    time_t now = time(NULL);

    if (now < fd_info->next_timeout) return;

    time_t next_timeout = INT_MAX;

    for (i = 0; i < watchers_maxfd(fd_info->watchers); i++) {
        /* if it's either in read or write set, there is a connection
         * behind that file descriptor */
        struct connection* cnx = collection_get_cnx_from_fd(fd_info->collection, i);
        if (cnx) {
            time_t timeout = udp_timeout(cnx);
            if (!timeout) continue; /* Not a UDP connection */
            if (cnx && (timeout <= now)) {
                print_message(msg_fd, "timed out UDP %d\n", cnx->target_sock);
                close(cnx->target_sock);
                watchers_del_read(fd_info->watchers, i);
                watchers_del_write(fd_info->watchers, i);
                collection_remove_cnx(fd_info->collection, cnx);
            } else {
                if (timeout < next_timeout) next_timeout = timeout;
            }
        }
    }

    if (next_timeout != INT_MAX)
        fd_info->next_timeout = next_timeout;
}

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
int udp_c2s_forward(int sockfd, struct loop_info* fd_info)
{
    char addr_str[NI_MAXHOST+1+NI_MAXSERV+1];
    struct sockaddr src_addr;
    struct addrinfo addrinfo;
    struct sslhcfg_protocols_item* proto;
    cnx_collection* collection = fd_info->collection;
    int max_fd = watchers_maxfd(fd_info->watchers);
    struct connection* cnx;
    ssize_t len;
    socklen_t addrlen;
    int res, target, out = -1;
    char data[65536]; /* Theoritical max is 65507 (https://en.wikipedia.org/wiki/User_Datagram_Protocol).
                         This will do.  Dynamic allocation is possible with the MSG_PEEK flag in recvfrom(2), but that'd imply
                         malloc/free overhead for each packet, when really 64K is not that much */

    udp_timeouts(fd_info);

    addrlen = sizeof(src_addr);
    len = recvfrom(sockfd, data, sizeof(data), 0, &src_addr, &addrlen);
    if (len < 0) {
        perror("recvfrom");
        return -1;
    }
    target = known_source(collection, max_fd, &src_addr, addrlen);
    addrinfo.ai_addr = &src_addr;
    addrinfo.ai_addrlen = addrlen;
    print_message(msg_probe_info, "received %ld UDP from %d:%s\n", 
                  len, target, sprintaddr(addr_str, sizeof(addr_str), &addrinfo));

    if (target == -1) {
        res = probe_buffer(data, len, &proto);
        /* First version: if we can't work out the protocol from the first
         * packet, drop it. Conceivably, we could store several packets to
         * run probes on packet sets */
        print_message(msg_probe_info, "UDP probed: %d\n", res);
        if (res != PROBE_MATCH) {
            return -1;
        }

        out = socket(proto->saddr->ai_family, SOCK_DGRAM, 0);
        res = set_nonblock(out);
        CHECK_RES_RETURN(res, "udp:socket:nonblock", -1);
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
    print_message(msg_fd, "sending %d to %s\n", 
            res, sprintaddr(data, sizeof(data), cnx->proto->saddr));
    return out;
}


void udp_s2c_forward(struct connection* cnx)
{
    int sockfd = cnx->target_sock;
    char data[65536];
    int res;

    res = recvfrom(sockfd, data, sizeof(data), 0, NULL, NULL);
    if ((res == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) return;
    CHECK_RES_DIE(res, "udp_listener/recvfrom");
    res = sendto(cnx->local_endpoint, data, res, 0,
                 &cnx->client_addr, cnx->addrlen);
    cnx->last_active = time(NULL);
}

