/*
   sslh-select: mono-processus server

# Copyright (C) 2007-2010  Yves Rutschle
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

#define __LINUX__

#include "common.h"
#include "probe.h"

const char* server_type = "sslh-select";

/* cnx_num_alloc is the number of connection to allocate at once (at start-up,
 * and then every time we get too many simultaneous connections: e.g. start
 * with 100 slots, then if we get more than 100 connections allocate another
 * 100 slots, and so on). We never free up connection structures. We try to
 * allocate as many structures at once as will fit in one page (which is 102
 * in sslh 1.9 on Linux on x86)
 */
static long cnx_num_alloc;

/* Make the file descriptor non-block  */
int set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    CHECK_RES_RETURN(flags, "fcntl");

    flags |= O_NONBLOCK;

    flags = fcntl(fd, F_SETFL, flags);
    CHECK_RES_RETURN(flags, "fcntl");

    return flags;
}

int tidy_connection(struct connection *cnx, fd_set *fds, fd_set *fds2)
{
    int i;

    for (i = 0; i < 2; i++) {
        if (cnx->q[i].fd != -1) {
            if (verbose)
                fprintf(stderr, "closing fd %d\n", cnx->q[i].fd);

            close(cnx->q[i].fd);
            FD_CLR(cnx->q[i].fd, fds);
            FD_CLR(cnx->q[i].fd, fds2);
            if (cnx->q[i].deferred_data)
                free(cnx->q[i].deferred_data);
        }
    }
    init_cnx(cnx);
    return 0;
}

/* if fd becomes higher than FD_SETSIZE, things won't work so well with FD_SET
 * and FD_CLR. Need to drop connections if we go above that limit */
int fd_is_in_range(int fd) {
    if (fd >= FD_SETSIZE) {
        log_message(LOG_ERR, "too many open file descriptor to monitor them all -- dropping connection\n");
        return 0;
    }
    return 1;
}

/* Accepts a connection from the main socket and assigns it to an empty slot.
 * If no slots are available, allocate another few. If that fails, drop the
 * connexion */
int accept_new_connection(int listen_socket, struct connection *cnx[], int* cnx_size) 
{
    int in_socket, free, i, res;
    struct connection *new;

    in_socket = accept(listen_socket, 0, 0);
    CHECK_RES_RETURN(in_socket, "accept");

    if (!fd_is_in_range(in_socket))
        return -1;

    res = set_nonblock(in_socket);
    if (res == -1) return -1;

    /* Find an empty slot */
    for (free = 0; (free < *cnx_size) && ((*cnx)[free].q[0].fd != -1); free++) {
        /* nothing */
    }
    if (free >= *cnx_size)  {
        if (verbose)
            fprintf(stderr, "buying more slots from the slot machine.\n");
        new = realloc(*cnx, (*cnx_size + cnx_num_alloc) * sizeof((*cnx)[0]));
        if (!new) {
            log_message(LOG_ERR, "unable to realloc -- dropping connection\n");
            return -1;
        }
        *cnx = new;
        *cnx_size += cnx_num_alloc;
        for (i = free; i < *cnx_size; i++) {
            init_cnx(&(*cnx)[i]); 
        }
    }
    (*cnx)[free].q[0].fd = in_socket;
    (*cnx)[free].state = ST_PROBING;
    (*cnx)[free].probe_timeout = time(NULL) + probing_timeout;

    if (verbose) 
        fprintf(stderr, "accepted fd %d on slot %d\n", in_socket, free);

    return in_socket;
}


/* Connect queue 1 of connection to SSL; returns new file descriptor */
int connect_queue(struct connection *cnx, fd_set *fds_r, fd_set *fds_w)
{
    struct queue *q = &cnx->q[1];

    q->fd = connect_addr(cnx, cnx->q[0].fd);
    if ((q->fd != -1) && fd_is_in_range(q->fd)) {
        log_connection(cnx);
        set_nonblock(q->fd);
        flush_deferred(q);
        if (q->deferred_data) {
            FD_SET(q->fd, fds_w);
        } else {
            FD_SET(q->fd, fds_r);
        }
        return q->fd;
    } else {
        tidy_connection(cnx, fds_r, fds_w);
        return -1;
    }
}

/* shovels data from active fd to the other
   returns after one socket closed or operation would block
 */
void shovel(struct connection *cnx, int active_fd, 
            fd_set *fds_r, fd_set *fds_w)
{
    struct queue *read_q, *write_q;

    read_q = &cnx->q[active_fd];
    write_q = &cnx->q[1-active_fd];

    if (verbose)
        fprintf(stderr, "activity on fd%d\n", read_q->fd);

    switch(fd2fd(write_q, read_q)) {
    case -1:
    case FD_CNXCLOSED:
        tidy_connection(cnx, fds_r, fds_w);
        break;

    case FD_STALLED:
        FD_SET(write_q->fd, fds_w);
        FD_CLR(read_q->fd, fds_r);
        break;

    default: /* Nothing */
        break;
    }
}

/* returns true if specified fd is initialised and present in fd_set */
int is_fd_active(int fd, fd_set* set)
{
    if (fd == -1) return 0;
    return FD_ISSET(fd, set);
}

/* Main loop: the idea is as follow:
 * - fds_r and fds_w contain the file descriptors to monitor in read and write
 * - When a file descriptor goes off, process it: read from it, write the data
 * to its corresponding pair.
 * - When a file descriptor blocks when writing, remove the read fd from fds_r,
 * move the data to a deferred buffer, and add the write fd to fds_w. Defered
 * buffer is allocated dynamically.
 * - When we can write to a file descriptor that has deferred data, we try to
 * write as much as we can. Once all data is written, remove the fd from fds_w
 * and add its corresponding pair to fds_r, free the buffer.
 *
 * That way, each pair of file descriptor (read from one, write to the other)
 * is monitored either for read or for write, but never for both.
 */
void main_loop(int listen_sockets[], int num_addr_listen)
{
    fd_set fds_r, fds_w;  /* reference fd sets (used to init the next 2) */
    fd_set readfds, writefds; /* working read and write fd sets */
    struct timeval tv;
    int max_fd, in_socket, i, j, res;
    struct connection *cnx;
    int num_cnx;  /* Number of connections in *cnx */
    int num_probing = 0; /* Number of connections currently probing 
                          * We use this to know if we need to time out of
                          * select() */

    FD_ZERO(&fds_r);
    FD_ZERO(&fds_w);

    for (i = 0; i < num_addr_listen; i++) {
        FD_SET(listen_sockets[i], &fds_r); 
        set_nonblock(listen_sockets[i]);
    }
    max_fd = listen_sockets[num_addr_listen-1] + 1;

    cnx_num_alloc = getpagesize() / sizeof(struct connection);

    num_cnx = cnx_num_alloc; /* Start with a set pool of slots */
    cnx = malloc(num_cnx * sizeof(struct connection));
    for (i = 0; i < num_cnx; i++)
        init_cnx(&cnx[i]);

    while (1)
    {
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = probing_timeout;

        memcpy(&readfds, &fds_r, sizeof(readfds));
        memcpy(&writefds, &fds_w, sizeof(writefds));

        if (verbose)
            fprintf(stderr, "selecting... max_fd=%d num_probing=%d\n", max_fd, num_probing);
        res = select(max_fd, &readfds, &writefds, NULL, num_probing ? &tv : NULL);
        if (res < 0)
            perror("select");


        /* Check main socket for new connections */
        for (i = 0; i < num_addr_listen; i++) {
            if (FD_ISSET(listen_sockets[i], &readfds)) {
                in_socket = accept_new_connection(listen_sockets[i], &cnx, &num_cnx);
                if (in_socket != -1)
                    num_probing++;

                if (in_socket > 0) {
                    FD_SET(in_socket, &fds_r);
                    if (in_socket >= max_fd)
                        max_fd = in_socket + 1;;
                }
                FD_CLR(listen_sockets[i], &readfds);
            }
        }

        /* Check all sockets for write activity */
        for (i = 0; i < num_cnx; i++) {
            if (cnx[i].q[0].fd != -1) {
                for (j = 0; j < 2; j++) {
                    if (is_fd_active(cnx[i].q[j].fd, &writefds)) {
                        res = flush_deferred(&cnx[i].q[j]);
                        if ((res == -1) && ((errno == EPIPE) || (errno == ECONNRESET))) {
                            if (cnx[i].state == ST_PROBING) num_probing--;
                            tidy_connection(&cnx[i], &fds_r, &fds_w);
                            if (verbose)
                                fprintf(stderr, "closed slot %d\n", i);
                        } else {
                            /* If no deferred data is left, stop monitoring the fd 
                             * for write, and restart monitoring the other one for reads*/
                            if (!cnx[i].q[j].deferred_data_size) {
                                FD_CLR(cnx[i].q[j].fd, &fds_w);
                                FD_SET(cnx[i].q[1-j].fd, &fds_r);
                            }
                        }
                    }
                }
            }
        }

        /* Check all sockets for read activity */
        for (i = 0; i < num_cnx; i++) {
            for (j = 0; j < 2; j++) {
                if (is_fd_active(cnx[i].q[j].fd, &readfds) || 
                    ((cnx[i].state == ST_PROBING) && (cnx[i].probe_timeout < time(NULL)))) {
                    if (verbose)
                        fprintf(stderr, "processing fd%d slot %d\n", j, i);

                    switch (cnx[i].state) {

                    case ST_PROBING:
                        if (j == 1) {
                            fprintf(stderr, "Activity on fd2 while probing, impossible\n");
                            dump_connection(&cnx[i]);
                            exit(1);
                        }

                        /* If timed out it's SSH, otherwise the client sent
                         * data so probe the protocol */
                        if ((cnx[i].probe_timeout < time(NULL))) {
                            cnx[i].proto = timeout_protocol();
                            if (verbose)
                                fprintf(stderr, "timeout, forwarding to %s\n", cnx[i].proto->description);
                        } else {
                            res = probe_client_protocol(&cnx[i]);
                            if (res == PROBE_AGAIN)
                                continue;
                        }

                        num_probing--;
                        cnx[i].state = ST_SHOVELING;

                        /* libwrap check if required for this protocol */
                        if (cnx[i].proto->service &&
                            check_access_rights(in_socket, cnx[i].proto->service)) {
                            tidy_connection(&cnx[i], &fds_r, &fds_w);
                            res = -1;
                        } else {
                            res = connect_queue(&cnx[i], &fds_r, &fds_w);
                        }

                        if (res >= max_fd)
                            max_fd = res + 1;;
                        break;

                    case ST_SHOVELING:
                        shovel(&cnx[i], j, &fds_r, &fds_w);
                        break;

                    default: /* illegal */
                        log_message(LOG_ERR, "Illegal connection state %d\n", cnx[i].state);
                        exit(1);
                    }
                }
            }
        }
    }
}


void start_shoveler(int listen_socket) {
    fprintf(stderr, "inetd mode is not supported in select mode\n");
    exit(1);
}


/* The actual main is in common.c: it's the same for both version of
 * the server
 */


