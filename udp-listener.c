/*
   udp-listener.c: handles demultiplexing UDP protocols

# Copyright (C) 2020-2022  Yves Rutschle
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

/* Incoming connections are of course all received on a single socket. Create a
 * hash that associates (incoming sockaddr) => struct connection*, so finding
 * the connection related to an incoming packet is fast.
 */



static int cnx_cmp(struct connection* cnx1, struct connection* cnx2)
{
    struct sockaddr_storage* addr1 = &cnx1->client_addr;
    socklen_t addrlen1 = cnx1->addrlen;

    struct sockaddr_storage* addr2 = &cnx2->client_addr;
    socklen_t addrlen2 = cnx2->addrlen;

    if (addrlen1 != addrlen2) return -1;

    return memcmp(addr1, addr2, addrlen1);
}

/* From an IP address, create something that's useable as a hash key.
 * Currently:
 * lowest bytes of remote port */
static int hash_make_key(hash_item new)
{
    struct sockaddr_storage* addr = &new->client_addr;
    //socklen_t addrlen = new->addrlen;
    struct sockaddr_in* addr4;
    struct sockaddr_in6* addr6;
    int out;

    switch (((struct sockaddr*)addr)->sa_family) {
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

static struct sslhcfg_protocols_item** udp_protocols;
static int udp_protocols_len = 0;

static void udp_protocol_list_init(void)
{
    for (int i = 0; i < cfg.protocols_len; i++) {
        struct sslhcfg_protocols_item* p = &cfg.protocols[i];
        if (p->is_udp) {
            udp_protocols_len++;
            udp_protocols = realloc(udp_protocols, udp_protocols_len * sizeof(*udp_protocols));
            CHECK_ALLOC(udp_protocols, "realloc");
            udp_protocols[udp_protocols_len-1] = p;
        }
    }
}

/* Configuration sanity check for UDP:
 * - If there is a listening address, there must be at least one target
 */
static void udp_sanity_check(void)
{
    int udp_present = 0;

    for (int i = 0; i < cfg.listen_len; i++) {
        struct sslhcfg_listen_item* p = &cfg.listen[i];
        if (p->is_udp) {
            udp_present = 1;
            break;
        }
    }

    if (udp_present && !udp_protocols_len) {
        print_message(msg_config_error, "At least one UDP target protocol must be specified.\n");
        exit(2);
    }
}

/* Init the UDP subsystem.
 * - Initialise the hash
 * - that's all, folks
 * */
void udp_init(struct loop_info* fd_info)
{
    fd_info->hash_sources = hash_init(cfg.udp_max_connections, &hash_make_key, &cnx_cmp);

    udp_protocol_list_init();
    udp_sanity_check();
}


/* Find if the specified source has been seen before.
 * If yes, returns file descriptor of connection
 * If not, returns -1
 * */
static int known_source(hash* h, struct sockaddr_storage* addr, socklen_t addrlen)
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


/* Double linked list utilities: push element at tail of list */
static void list_push(dl_list* list, struct connection* cnx)
{
    cnx->timeout_next = NULL;

    if (!list->head) {
        cnx->timeout_prev = NULL;
        list->head = cnx;
    }

    if (list->tail) {
        list->tail->timeout_next = cnx;
        cnx->timeout_prev = list->tail;
    }

    list->tail = cnx;
}

/* Double linked list utilities: remove element */
static void list_remove(dl_list* list, struct connection* cnx)
{
    if (list->head == cnx) list->head = cnx->timeout_next;
    if (list->tail == cnx) list->tail = cnx->timeout_prev;

    if (cnx->timeout_prev)
        cnx->timeout_prev->timeout_next = cnx->timeout_next;

    if (cnx->timeout_next)
        cnx->timeout_next->timeout_prev = cnx->timeout_prev;
}

/* Timeouts are managed with one list for each protocol. Whenever a connection
 * is active, it gets moved to the end of the list. Each call will pop the
 * first elements that have timed out and free their resources.
 *
 * This gets called every time a UDP packet is received from the outside, i.e.
 * every time we might need to free up resources. If no packets come in, we
 * don't time out anything, as we don't need the resources.
 * */
void udp_timeouts(struct loop_info* fd_info)
{
    time_t now = time(NULL);

    for (int i = 0; i < cfg.protocols_len; i++) {
        struct connection *cnx = cfg.protocols[i].timeouts.head;
        while (cnx && (now - cnx->last_active > cfg.protocols[i].udp_timeout)) {
            print_message(msg_fd, "timed out UDP %d\n", cnx->target_sock);
            tidy_connection(cnx, fd_info);

            cnx = cfg.protocols[i].timeouts.head;
        }
    }
}

void udp_tidy(struct connection* cnx, struct loop_info* fd_info)
{
    close(cnx->target_sock);
    hash_remove(fd_info->hash_sources, cnx);
    list_remove(&cnx->proto->timeouts, cnx);
}

/* Mark the connection was active */
static void mark_active(struct connection* cnx)
{
    cnx->last_active = time(NULL);

    dl_list* list = &cnx->proto->timeouts;

    list_remove(list, cnx);
    list_push(list, cnx);
}


/* Creates a new non-blocking socket */
static int nonblocking_socket(struct sslhcfg_protocols_item* proto)
{
    int res;

    if (proto->resolve_on_forward) {
        res = resolve_split_name(&(proto->saddr), proto->host,
                                 proto->port);
        if (res) return -1;
    }

    int out = socket(proto->saddr->ai_family, SOCK_DGRAM, 0);
    res = set_nonblock(out);
    if (res == -1) {
        print_message(msg_system_error, "%s:%d:%s:%d:%s\n", __FILE__, __LINE__, "udp:socket:nonblock", errno, strerror(errno));
        close(out);
        return -1;
    }
    return out;
}


/* Process UDP coming from outside (client towards server)
 * If it's a new source, probe; otherwise, forward to previous target 
 * Returns: newly allocate connections, for new connections
 * NULL otherwise
 * */
struct connection* udp_c2s_forward(int sockfd, struct loop_info* fd_info)
{
    char addr_str[NI_MAXHOST+1+NI_MAXSERV+1];
    struct sockaddr_storage src_addr;
    struct addrinfo addrinfo;
    struct sslhcfg_protocols_item* proto;
    cnx_collection* collection = fd_info->collection;
    struct connection* cnx;
    ssize_t len;
    socklen_t addrlen;
    ssize_t res;
    int target, out = -1;
    char data[65536]; /* Theoretical max is 65507 (https://en.wikipedia.org/wiki/User_Datagram_Protocol).
                         This will do.  Dynamic allocation is possible with the MSG_PEEK flag in recvfrom(2), but that'd imply
                         malloc/free overhead for each packet, when really 64K is not that much */


    udp_timeouts(fd_info);

    addrlen = sizeof(src_addr);
    len = recvfrom(sockfd, data, sizeof(data), 0, (struct sockaddr*) &src_addr, &addrlen);
    if (len < 0) {
        perror("recvfrom");
        return NULL;
    }
    target = known_source(fd_info->hash_sources, &src_addr, addrlen);
    addrinfo.ai_addr = (struct sockaddr*) &src_addr;
    addrinfo.ai_addrlen = addrlen;
    print_message(msg_probe_info, "received %ld UDP from %d:%s\n", 
                  len, target, sprintaddr(addr_str, sizeof(addr_str), &addrinfo));

    if (target == -1) {
        res = probe_buffer(data, (int)len, udp_protocols, udp_protocols_len, &proto);
        /* First version: if we can't work out the protocol from the first
         * packet, drop it. Conceivably, we could store several packets to
         * run probes on packet sets */
        print_message(msg_probe_info, "UDP probed: %d\n", res);
        if (res != PROBE_MATCH) {
            return NULL;
        }

        out = nonblocking_socket(proto);
        if (out == -1) return NULL;
        struct connection* cnx = collection_alloc_cnx_from_fd(collection, out);
        if (!cnx) return NULL;
        target = out;
        cnx->target_sock = out;
        cnx->proto = proto;
        cnx->type = SOCK_DGRAM;
        cnx->client_addr = src_addr;
        cnx->addrlen = addrlen;
        cnx->local_endpoint = sockfd;

        res = new_source(fd_info->hash_sources, cnx);
        if (res == -1) {
            print_message(msg_connections_error, "Out of hash space for new incoming UDP connection -- increase udp_max_connections");
            collection_remove_cnx(collection, cnx);
            return NULL;
        }
    }
    cnx = collection_get_cnx_from_fd(collection, target);

    /* at this point src is the UDP connection */
    res = sendto(cnx->target_sock, data, len, 0,
                 cnx->proto->saddr->ai_addr, cnx->proto->saddr->ai_addrlen);
    mark_active(cnx);
    print_message(msg_fd, "sending %d to %s\n", 
            res, sprintaddr(data, sizeof(data), cnx->proto->saddr));

    return cnx;
}

void udp_s2c_forward(struct connection* cnx)
{
    int sockfd = cnx->target_sock;
    char data[65536];
    ssize_t res;

    res = recvfrom(sockfd, data, sizeof(data), 0, NULL, NULL);
    if ((res == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) return;
    CHECK_RES_DIE(res, "udp_listener/recvfrom");
    res = sendto(cnx->local_endpoint, data, res, 0,
                 (struct sockaddr*)&cnx->client_addr, cnx->addrlen);
    mark_active(cnx);
}

