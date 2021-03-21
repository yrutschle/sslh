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

#define __LINUX__

#include "common.h"
#include "probe.h"
#include "collection.h"

const char* server_type = "sslh-select";

/* Global state for a select() loop */
struct select_info {
    int max_fd;   /* Highest fd number to pass to select() */
    int num_probing;     /* Number of connections currently probing 
                          * We use this to know if we need to time out of
                          * select() */
    fd_set fds_r, fds_w;  /* reference fd sets (used to init working copies) */
};




/* Make the file descriptor non-block  */
static int set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    CHECK_RES_RETURN(flags, "fcntl", -1);

    flags |= O_NONBLOCK;

    flags = fcntl(fd, F_SETFL, flags);
    CHECK_RES_RETURN(flags, "fcntl", -1);

    return flags;
}

static int tidy_connection(struct connection *cnx, fd_set *fds, fd_set *fds2)
{
    int i;

    for (i = 0; i < 2; i++) {
        if (cnx->q[i].fd != -1) {
            if (cfg.verbose)
                fprintf(stderr, "closing fd %d\n", cnx->q[i].fd);

            FD_CLR(cnx->q[i].fd, fds);
            FD_CLR(cnx->q[i].fd, fds2);
            close(cnx->q[i].fd);
            if (cnx->q[i].deferred_data)
                free(cnx->q[i].deferred_data);
        }
    }
    init_cnx(cnx);
    return 0;
}

/* if fd becomes higher than FD_SETSIZE, things won't work so well with FD_SET
 * and FD_CLR. Need to drop connections if we go above that limit */
static int fd_is_in_range(int fd) {
    if (fd >= FD_SETSIZE) {
        log_message(LOG_ERR, "too many open file descriptor to monitor them all -- dropping connection\n");
        return 0;
    }
    return 1;
}

/* Accepts a connection from the main socket and assigns it to an empty slot.
 * If no slots are available, allocate another few. If that fails, drop the
 * connexion */
static int accept_new_connection(int listen_socket, struct cnx_collection *collection)
{
    int in_socket, res;

    in_socket = accept(listen_socket, 0, 0);
    CHECK_RES_RETURN(in_socket, "accept", -1);

    if (!fd_is_in_range(in_socket)) {
        close(in_socket);
        return -1;
    }

    res = set_nonblock(in_socket);
    if (res == -1) {
        close(in_socket);
        return -1;
    }

    res = collection_add_fd(collection, in_socket);
    if (res == -1) {
        close(in_socket);
        return -1;
    }

    return in_socket;
}


/* Connect queue 1 of connection to SSL; returns new file descriptor */
static int connect_queue(struct connection *cnx, fd_set *fds_r, fd_set *fds_w)
{
    struct queue *q = &cnx->q[1];

    q->fd = connect_addr(cnx, cnx->q[0].fd);
    if ((q->fd != -1) && fd_is_in_range(q->fd)) {
        log_connection(NULL, cnx);
        set_nonblock(q->fd);
        flush_deferred(q);
        if (q->deferred_data) {
            FD_SET(q->fd, fds_w);
            FD_CLR(cnx->q[0].fd, fds_r);
        }
        FD_SET(q->fd, fds_r);
        return q->fd;
    } else {
        tidy_connection(cnx, fds_r, fds_w);
        return -1;
    }
}

/* shovels data from active fd to the other
   returns after one socket closed or operation would block
 */
static void shovel(struct connection *cnx, int active_fd, 
            fd_set *fds_r, fd_set *fds_w)
{
    struct queue *read_q, *write_q;

    read_q = &cnx->q[active_fd];
    write_q = &cnx->q[1-active_fd];

    if (cfg.verbose)
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

/* shovels data from one fd to the other and vice-versa
   returns after one socket closed
 */
static void shovel_single(struct connection *cnx)
{
   fd_set fds_r, fds_w;
   int res, i;
   int max_fd = MAX(cnx->q[0].fd, cnx->q[1].fd) + 1;

   FD_ZERO(&fds_r);
   FD_ZERO(&fds_w);
   while (1) {
      for (i = 0; i < 2; i++) {
         if (cnx->q[i].deferred_data_size) {
            FD_SET(cnx->q[i].fd, &fds_w);
            FD_CLR(cnx->q[1-i].fd, &fds_r);
         } else {
            FD_CLR(cnx->q[i].fd, &fds_w);
            FD_SET(cnx->q[1-i].fd, &fds_r);
         }
      }

      res = select(
                   max_fd,
                   &fds_r,
                   &fds_w,
                   NULL,
                   NULL
                  );
      CHECK_RES_DIE(res, "select");

      for (i = 0; i < 2; i++) {
          if (FD_ISSET(cnx->q[i].fd, &fds_w)) {
              res = flush_deferred(&cnx->q[i]);
              if ((res == -1) && ((errno == EPIPE) || (errno == ECONNRESET))) {
                  if (cfg.verbose)
                      fprintf(stderr, "%s socket closed\n", i ? "server" : "client");
                  return;
              }
          }
          if (FD_ISSET(cnx->q[i].fd, &fds_r)) {
              res = fd2fd(&cnx->q[1-i], &cnx->q[i]);
              if (!res) {
                  if (cfg.verbose)
                      fprintf(stderr, "socket closed\n");
                  return;
              }
          }
      }
   }
}

/* Child process that makes internal connection and proxies
 */
static void connect_proxy(struct connection *cnx)
{
    int in_socket;
    int out_socket;

    /* Minimize the file descriptor value to help select() */
    in_socket = dup(cnx->q[0].fd);
    if (in_socket == -1) {
        in_socket = cnx->q[0].fd;
    } else {
        close(cnx->q[0].fd);
        cnx->q[0].fd = in_socket;
    }

    /* Connect the target socket */
    out_socket = connect_addr(cnx, in_socket);
    CHECK_RES_DIE(out_socket, "connect");

    cnx->q[1].fd = out_socket;

    log_connection(NULL, cnx);

    shovel_single(cnx);

    close(in_socket);
    close(out_socket);

    if (cfg.verbose)
        fprintf(stderr, "connection closed down\n");

    exit(0);
}

/* returns true if specified fd is initialised and present in fd_set */
static int is_fd_active(int fd, fd_set* set)
{
    if (fd == -1) return 0;
    return FD_ISSET(fd, set);
}


/* Process read activity on a socket in probe state 
 * IN/OUT cnx: connection data, updated if connected
 * IN/OUT info: updated if connected
 * */
static void probing_read_process(struct connection* cnx, struct select_info* fd_info)
{
    int res;

    /* If timed out it's SSH, otherwise the client sent
     * data so probe the protocol */
    if ((cnx->probe_timeout < time(NULL))) {
        cnx->proto = timeout_protocol();
        if (cfg.verbose) 
            log_message(LOG_INFO, 
                        "timed out, connect to %s\n", 
                        cnx->proto->name);
    } else {
        res = probe_client_protocol(cnx);
        if (res == PROBE_AGAIN)
            return;
    }

    fd_info->num_probing--;
    cnx->state = ST_SHOVELING;

    /* libwrap check if required for this protocol */
    if (cnx->proto->service &&
        check_access_rights(cnx->q[0].fd, cnx->proto->service)) {
        tidy_connection(cnx, &fd_info->fds_r, &fd_info->fds_w);
        res = -1;
    } else if (cnx->proto->fork) {
        switch (fork()) {
        case 0:  /* child */
            /* TODO: close all file descriptors except 2 */
            /* free(cnx); */
            connect_proxy(cnx);
            exit(0);
        case -1: log_message(LOG_ERR, "fork failed: err %d: %s\n", errno, strerror(errno));
                 break;
        default: /* parent */
                 break;
        }
        tidy_connection(cnx, &fd_info->fds_r, &fd_info->fds_w);
        res = -1;
    } else {
        res = connect_queue(cnx, &fd_info->fds_r, &fd_info->fds_w);
    }

    if (res >= fd_info->max_fd)
        fd_info->max_fd = res + 1;;
}


/* Process a connection that is active in read */
static void cnx_read_process(struct connection* cnx, int active_q, struct select_info* fd_info)
{
    switch (cnx->state) {

    case ST_PROBING:
        if (active_q == 1) {
            fprintf(stderr, "Activity on fd2 while probing, impossible\n");
            dump_connection(cnx);
            exit(1);
        }

        probing_read_process(cnx, fd_info);

        break;

    case ST_SHOVELING:
        shovel(cnx, active_q, &fd_info->fds_r, &fd_info->fds_w);
        break;

    default: /* illegal */
        log_message(LOG_ERR, "Illegal connection state %d\n", cnx->state);
        exit(1);
    }
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
    struct select_info fd_info = {0};

    fd_set readfds, writefds; /* working read and write fd sets */
    struct timeval tv;
    int i, j, res;
    int in_socket = 0;
    cnx_collection* collection;

    fd_info.num_probing = 0; 
    FD_ZERO(&fd_info.fds_r);
    FD_ZERO(&fd_info.fds_w);

    for (i = 0; i < num_addr_listen; i++) {
        FD_SET(listen_sockets[i].socketfd, &fd_info.fds_r); 
        set_nonblock(listen_sockets[i].socketfd);
    }
    fd_info.max_fd = listen_sockets[num_addr_listen-1].socketfd + 1;

    collection = collection_init();

    while (1)
    {
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = cfg.timeout;

        memcpy(&readfds, &fd_info.fds_r, sizeof(readfds));
        memcpy(&writefds, &fd_info.fds_w, sizeof(writefds));

        if (cfg.verbose)
            fprintf(stderr, "selecting... max_fd=%d num_probing=%d\n", 
                                          fd_info.max_fd, fd_info.num_probing);
        res = select(fd_info.max_fd, &readfds, &writefds, 
                     NULL, fd_info.num_probing ? &tv : NULL);
        if (res < 0)
            perror("select");

        /* Check main socket for new connections */
        for (i = 0; i < num_addr_listen; i++) {
            if (FD_ISSET(listen_sockets[i].socketfd, &readfds)) {
                in_socket = accept_new_connection(listen_sockets[i].socketfd, collection);
                if (in_socket > 0) {
                    fd_info.num_probing++;
                    FD_SET(in_socket, &fd_info.fds_r);
                    if (in_socket >= fd_info.max_fd)
                        fd_info.max_fd = in_socket + 1;;
                }
            }
        }

        /* Check all sockets for write activity */
        for (i = 0; i < collection_get_length(collection); i++) {
            struct connection* cnx = collection_get_cnx(collection, i);
            if (cnx->q[0].fd != -1) {
                for (j = 0; j < 2; j++) {
                    if (is_fd_active(cnx->q[j].fd, &writefds)) {
                        res = flush_deferred(&cnx->q[j]);
                        if ((res == -1) && ((errno == EPIPE) || (errno == ECONNRESET))) {
                            if (cnx->state == ST_PROBING) fd_info.num_probing--;
                            tidy_connection(cnx, &fd_info.fds_r, &fd_info.fds_w);
                            if (cfg.verbose)
                                fprintf(stderr, "closed slot %d\n", i);
                        } else {
                            /* If no deferred data is left, stop monitoring the fd 
                             * for write, and restart monitoring the other one for reads*/
                            if (!cnx->q[j].deferred_data_size) {
                                FD_CLR(cnx->q[j].fd, &fd_info.fds_w);
                                FD_SET(cnx->q[1-j].fd, &fd_info.fds_r);
                            }
                        }
                    }
                }
            }
        }

        /* Check all sockets for read activity */
        for (i = 0; i < collection_get_length(collection); i++) {
            struct connection* cnx = collection_get_cnx(collection, i);
            for (j = 0; j < 2; j++) {
                if (is_fd_active(cnx->q[j].fd, &readfds) || 
                    ((cnx->state == ST_PROBING) && (cnx->probe_timeout < time(NULL)))) {
                    if (cfg.verbose)
                        fprintf(stderr, "processing read fd%d slot %d\n", j, i);

                    cnx_read_process(cnx, j, &fd_info);
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


