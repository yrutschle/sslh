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

typedef struct connection* hash_item;
#include "hash.h"


/* returns date at which this socket times out. */
static int udp_timeout(struct connection* cnx)
{
    if (cnx->type != SOCK_DGRAM) return 0; /* Not a UDP connection */

    return cnx->proto->udp_timeout + cnx->last_active;
}

/* Incoming connections are of course all received on a single socket. Create a
 * hash that associates (incoming sockaddr) => struct connection*, so finding
 * the connection related to an incoming packet is fast.
 */



static int cnx_cmp(struct connection* cnx1, struct connection* cnx2)
{
    struct sockaddr* addr1 = &cnx1->client_addr;
    socklen_t addrlen1 = cnx1->addrlen;

    struct sockaddr* addr2 = &cnx2->client_addr;
    socklen_t addrlen2 = cnx2->addrlen;

    if (addrlen1 != addrlen2) return -1;

    return memcmp(addr1, addr2, addrlen1);
}

/* From an IP address, create something that's useable as a hash key.
 * Currently:
 * lowest bytes of remote port */
static int hash_make_key(hash_item new)
{
    struct sockaddr* addr = &new->client_addr;
    //socklen_t addrlen = new->addrlen;
    struct sockaddr_in* addr4;
    struct sockaddr_in6* addr6;
    int out;

    switch (addr->sa_family) {
    case AF_INET:
        addr4 = (struct sockaddr_in*)addr;
        out = addr4->sin_port;
        break;

    case AF_INET6:
        addr6 = (struct sockaddr_in6*)addr;
        out = addr6->sin6_port;
        break;

    default: /* Just use the first bytes, skipping the address family */
        out = ((char*)addr)[2];
        break;
    }
    return out;
}

/* Init the UDP subsystem.
 * - Initialise the hash
 * - that's all, folks
 * */
void udp_init(struct loop_info* fd_info)
{
    fd_info->hash_sources = hash_init(&hash_make_key, &cnx_cmp);
}


/* Find if the specified source has been seen before.
 * If yes, returns file descriptor of connection
 * If not, returns -1
 * */
static int known_source(hash* h, struct sockaddr* addr, socklen_t addrlen)
{
    struct connection search;
    search.client_addr = *addr;
    search.addrlen = addrlen;

    struct connection* cnx = hash_find(h, &search);
    if (!cnx) return -1;
    return cnx->q[0].fd;
}



static int new_source(hash* h, struct connection* new)
{
    return hash_insert(h, new);
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
    time_t now = time(NULL);

    if (now < fd_info->next_timeout) return;

    time_t next_timeout = INT_MAX;

    for (int i = 0; i < watchers_maxfd(fd_info->watchers); i++) {
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
                hash_remove(fd_info->hash_sources, cnx);
            } else {
                if (timeout < next_timeout) next_timeout = timeout;
            }
        }
    }

    if (next_timeout != INT_MAX)
        fd_info->next_timeout = next_timeout;
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
    target = known_source(fd_info->hash_sources, &src_addr, addrlen);
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

        res = new_source(fd_info->hash_sources, cnx);
        if (res == -1) {
            print_message(msg_connections_error, "Out of hash space for new incoming UDP connection");
            collection_remove_cnx(collection, cnx);
            return -1;
        }
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

