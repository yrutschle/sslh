/*
   sslh-select: mono-processus server

# Copyright (C) 2007-2021  Yves Rutschle
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

/* Why use select(2) rather than poll(2)?
 * No real reason except that's how it was written at first. This article:
 * https://daniel.haxx.se/docs/poll-vs-select.html suggests that over a few
 * hundred file descriptors, both become very slow, so there is little
 * incentive to move to poll() to support more than FD_SETSIZE (which is 1024
 * on many Linux. To support large numbers of descriptors, either use the fork
 * version, or we'll have to write a new version based on libev. */

#define __LINUX__

#include <limits.h>

#include "common.h"
#include "probe.h"
#include "udp-listener.h"
#include "collection.h"
#include "gap.h"
#include "log.h"

const char* server_type = "sslh-select";

/* watcher type for a select() loop */
typedef struct watchers {
    fd_set fds_r, fds_w;  /* reference fd sets (used to init working copies) */
    int max_fd;   /* Highest fd number to pass to select() */
} watchers;
#define WATCHERS_TYPE_DEFINED /* To notify processes.h */

#include "processes.h"

void watchers_init(watchers* w)
{
    FD_ZERO(&w->fds_r);
    FD_ZERO(&w->fds_w);
}

void watchers_add_read(watchers* w, int fd)
{
    FD_SET(fd, &w->fds_r); 
    if (fd > w->max_fd)
        w->max_fd = fd + 1;
}

void watchers_del_read(watchers* w, int fd)
{
    FD_CLR(fd, &w->fds_r);
}

void watchers_add_write(watchers* w, int fd)
{
    FD_SET(fd, &w->fds_w); 
    if (fd > w->max_fd)
        w->max_fd = fd + 1;
}

void watchers_del_write(watchers* w, int fd)
{
    FD_CLR(fd, &w->fds_w);
}
/* /end watchers */




static int tidy_connection(struct connection *cnx, struct loop_info* fd_info)
{
    int i;

    for (i = 0; i < 2; i++) {
        if (cnx->q[i].fd != -1) {
            print_message(msg_fd, "closing fd %d\n", cnx->q[i].fd);

            watchers_del_read(&fd_info->watchers, cnx->q[i].fd);
            watchers_del_write(&fd_info->watchers, cnx->q[i].fd);
            close(cnx->q[i].fd);
            if (cnx->q[i].deferred_data)
                free(cnx->q[i].deferred_data);
        }
    }
    collection_remove_cnx(fd_info->collection, cnx);
    return 0;
}

/* if fd becomes higher than FD_SETSIZE, things won't work so well with FD_SET
 * and FD_CLR. Need to drop connections if we go above that limit */
static int fd_is_in_range(int fd) {
    if (fd >= FD_SETSIZE) {
        print_message(msg_system_error, "too many open file descriptor to monitor them all -- dropping connection\n");
        return 0;
    }
    return 1;
}



/* Connect queue 1 of connection to SSL; returns new file descriptor */
static int connect_queue(struct connection* cnx,
                         struct loop_info* fd_info)
{
    struct queue *q = &cnx->q[1];

    q->fd = connect_addr(cnx, cnx->q[0].fd, NON_BLOCKING);
    if ((q->fd != -1) && fd_is_in_range(q->fd)) {
        log_connection(NULL, cnx);
        flush_deferred(q);
        if (q->deferred_data) {
            FD_SET(q->fd, &fd_info->watchers.fds_w);
            FD_CLR(cnx->q[0].fd, &fd_info->watchers.fds_r);
        }
        FD_SET(q->fd, &fd_info->watchers.fds_r);
        collection_add_fd(fd_info->collection, cnx, q->fd);
        return q->fd;
    } else {
        tidy_connection(cnx, fd_info);
        return -1;
    }
}


/* Returns the queue index that contains the specified file descriptor */
int active_queue(struct connection* cnx, int fd)
{
    if (cnx->q[0].fd == fd) return 0;
    if (cnx->q[1].fd == fd) return 1;

    print_message(msg_int_error, "file descriptor %d not found in connection object\n", fd);
    return -1;
}



/* Check all connections to see if a UDP connections has timed out, then free
 * it. At the same time, keep track of the closest, next timeout. Only do the
 * search through connections if that timeout actually happened. If the
 * connection that would have timed out has had activity, it doesn't matter: we
 * go through connections to find the next timeout, which was needed anyway. */
static void udp_timeouts(struct loop_info* fd_info)
{
    time_t now = time(NULL);

    if (now < fd_info->next_timeout) return;

    time_t next_timeout = INT_MAX;

    for (int i = 0; i < fd_info->watchers.max_fd; i++) {
        /* if it's either in read or write set, there is a connection
         * behind that file descriptor */
        if (FD_ISSET(i, &fd_info->watchers.fds_r) || FD_ISSET(i, &fd_info->watchers.fds_w)) {
            struct connection* cnx = collection_get_cnx_from_fd(fd_info->collection, i);
            if (cnx) {
                time_t timeout = udp_timeout(cnx);
                if (!timeout) continue; /* Not a UDP connection */
                if (cnx && (timeout <= now)) {
                    print_message(msg_fd, "timed out UDP %d\n", cnx->target_sock);
                    close(cnx->target_sock);
                    watchers_del_read(&fd_info->watchers, i);
                    watchers_del_write(&fd_info->watchers, i);
                    collection_remove_cnx(fd_info->collection, cnx);
                } else {
                    if (timeout < next_timeout) next_timeout = timeout;
                }
            }
        }
    }

    if (next_timeout != INT_MAX)
        fd_info->next_timeout = next_timeout;
}

/* Main loop: the idea is as follow:
 * - fds_r and fds_w contain the file descriptors to monitor in read and write
 * - When a file descriptor goes off, process it: read from it, write the data
 * to its corresponding pair.
 * - When a file descriptor blocks when writing, remove the read fd from fds_r,
 * move the data to a deferred buffer, and add the write fd to fds_w. Deferred
 * buffer is allocated dynamically.
 * - When we can write to a file descriptor that has deferred data, we try to
 * write as much as we can. Once all data is written, remove the fd from fds_w
 * and add its corresponding pair to fds_r, free the buffer.
 *
 * That way, each pair of file descriptor (read from one, write to the other)
 * is monitored either for read or for write, but never for both.
 */
void main_loop(struct listen_endpoint listen_sockets[], int num_addr_listen)
{
    struct loop_info fd_info = {0};
    fd_set readfds, writefds; /* working read and write fd sets */
    struct timeval tv;
    int i, res;

    fd_info.num_probing = 0; 
    fd_info.probing_list = gap_init(0);

    watchers_init(&fd_info.watchers);

    for (i = 0; i < num_addr_listen; i++) {
        watchers_add_read(&fd_info.watchers, listen_sockets[i].socketfd);
        set_nonblock(listen_sockets[i].socketfd);
    }

    fd_info.collection = collection_init(fd_info.watchers.max_fd);

    while (1)
    {
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = cfg.timeout;

        memcpy(&readfds, &fd_info.watchers.fds_r, sizeof(readfds));
        memcpy(&writefds, &fd_info.watchers.fds_w, sizeof(writefds));

        print_message(msg_fd, "selecting... max_fd=%d num_probing=%d\n", 
                                          fd_info.watchers.max_fd, fd_info.num_probing);
        res = select(fd_info.watchers.max_fd, &readfds, &writefds, 
                     NULL, fd_info.num_probing ? &tv : NULL);
        if (res < 0)
            perror("select");


        /* UDP timeouts: clear out connections after some idle time */
        udp_timeouts(&fd_info);

        /* Check main socket for new connections */
        for (i = 0; i < num_addr_listen; i++) {
            if (FD_ISSET(listen_sockets[i].socketfd, &readfds)) {
                cnx_accept_process(&fd_info, &listen_sockets[i]);

                if (!fd_is_in_range(0 /*TODO: retrieve fd */ )) {
                    /* TODO: drop the connection */
                }

                /* don't also process it as a read socket */
                FD_CLR(listen_sockets[i].socketfd, &readfds);
            }
        }

        /* Check all sockets for write activity */
        for (i = 0; i < fd_info.watchers.max_fd; i++) {
            if (FD_ISSET(i, &writefds)) {
                cnx_write_process(&fd_info, i);
            }
        }

        /* Check sockets in probing state for timeouts */
        for (i = 0; i < fd_info.num_probing; i++) {
            struct connection* cnx = gap_get(fd_info.probing_list, i);
            if (!cnx || cnx->state != ST_PROBING) {
                print_message(msg_int_error, "Inconsistent probing: cnx=%0xp\n", cnx);
                if (cnx)
                    print_message(msg_int_error, "Inconsistent probing: state=%d\n", cnx);
                exit(1);
            }
            if (cnx->probe_timeout < time(NULL)) {
                print_message(msg_fd, "timeout slot %d\n", i);
                probing_read_process(cnx, &fd_info);
            }
        }

        /* Check all sockets for read activity */
        for (i = 0; i < fd_info.watchers.max_fd; i++) {
            /* Check if it's active AND currently monitored (if a connection
             * died, it gets tidied, which closes both sockets, but readfs does
             * not know about that */
            if (FD_ISSET(i, &readfds) && FD_ISSET(i, &fd_info.watchers.fds_r)) {
                cnx_read_process(&fd_info, i);
            }
        }
    }
}


void start_shoveler(int listen_socket) {
    print_message(msg_config_error, "inetd mode is not supported in select mode\n");
    exit(1);
}


/* The actual main is in common.c: it's the same for both version of
 * the server
 */


