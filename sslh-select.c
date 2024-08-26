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
 * on many Linux. To support large numbers of descriptors efficiently, either use sslh-fork
 * or sslh-ev. */

#define __LINUX__

#include "common.h"
#include "probe.h"
#include "tcp-listener.h"
#include "udp-listener.h"
#include "collection.h"
#include "processes.h"
#include "gap.h"
#include "log.h"

const char* server_type = "sslh-select";

/* watcher type for a select() loop */
struct watchers {
    fd_set fds_r, fds_w;  /* reference fd sets (used to init working copies) */
    int max_fd;   /* Highest fd number to pass to select() */
};


static void watchers_init(watchers** w, struct listen_endpoint* listen_sockets,
                          int num_addr_listen)
{
    *w = malloc(sizeof(**w));
    CHECK_ALLOC(*w, "malloc");

    memset(*w, 0, sizeof(**w));
    FD_ZERO(&(*w)->fds_r);
    FD_ZERO(&(*w)->fds_w);

    for (int i = 0; i < num_addr_listen; i++) {
        watchers_add_read(*w, listen_sockets[i].socketfd);
        set_nonblock(listen_sockets[i].socketfd);
    }
}

void watchers_add_read(watchers* w, int fd)
{
    FD_SET(fd, &w->fds_r); 
    if (fd + 1 > w->max_fd)
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




/* if fd becomes higher than FD_SETSIZE, things won't work so well with FD_SET
 * and FD_CLR. Need to drop connections if we go above that limit */
static int fd_out_of_range(int fd) {
    if (fd >= FD_SETSIZE) {
        print_message(msg_system_error, "too many open file descriptor to monitor them all -- dropping connection\n");
        return 1;
    }
    return 0;
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
    udp_init(&fd_info);
    tcp_init();

    watchers_init(&fd_info.watchers, listen_sockets, num_addr_listen);

    fd_info.collection = collection_init(fd_info.watchers->max_fd);

    while (1)
    {
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = cfg.timeout;

        memcpy(&readfds, &fd_info.watchers->fds_r, sizeof(readfds));
        memcpy(&writefds, &fd_info.watchers->fds_w, sizeof(writefds));

        print_message(msg_fd, "selecting... max_fd=%d num_probing=%d\n",
                                          fd_info.watchers->max_fd, fd_info.num_probing);
        res = select(fd_info.watchers->max_fd, &readfds, &writefds,
                     NULL, fd_info.num_probing ? &tv : NULL);
        if (res < 0)
            perror("select");

        /* Check main socket for new connections */
        for (i = 0; i < num_addr_listen; i++) {
            if (FD_ISSET(listen_sockets[i].socketfd, &readfds)) {
                struct connection* new_cnx = cnx_accept_process(&fd_info, &listen_sockets[i]);

                if (fd_out_of_range(new_cnx->q[0].fd))
                    tidy_connection(new_cnx, &fd_info);

                /* don't also process it as a read socket */
                FD_CLR(listen_sockets[i].socketfd, &readfds);
            }
        }

        /* Check all sockets for write activity */
        for (i = 0; i < fd_info.watchers->max_fd; i++) {
            /* Check if it's active AND currently monitored (if a connection
             * died, it gets tidied, which closes both sockets, but writefs does
             * not know about that */
            if (FD_ISSET(i, &writefds) && FD_ISSET(i, &fd_info.watchers->fds_w)) {
                cnx_write_process(&fd_info, i);
            }
        }

        /* Check sockets in probing state for timeouts */
        for (i = 0; i < fd_info.num_probing; i++) {
            struct connection* cnx = gap_get(fd_info.probing_list, i);
            if (!cnx || cnx->state != ST_PROBING) {
                print_message(msg_int_error, "Inconsistent probing: cnx=0x%p\n", cnx);
                if (cnx)
                    print_message(msg_int_error, "Inconsistent probing: state=%d\n", cnx->state);
                exit(1);
            }
            if (cnx->probe_timeout < time(NULL)) {
                print_message(msg_fd, "timeout slot %d\n", i);
                probing_read_process(cnx, &fd_info);
            }
        }

        /* Check all sockets for read activity */
        for (i = 0; i < fd_info.watchers->max_fd; i++) {
            /* Check if it's active AND currently monitored (if a connection
             * died, it gets tidied, which closes both sockets, but readfs does
             * not know about that */
            if (FD_ISSET(i, &readfds) && FD_ISSET(i, &fd_info.watchers->fds_r)) {
                cnx_read_process(&fd_info, i);
            }
        }
    }
}


void start_shoveler(int listen_socket) {
    print_message(msg_config_error, "inetd mode is not supported in select mode\n");
    exit(1);
}


/* The actual main is in sslh-main.c: it's the same for all versions of
 * the server
 */


