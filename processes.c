/* 
  Processes that are common to sslh-ev and sslh-select
 
# Copyright (C) 2021  Yves Rutschle
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

#include "udp-listener.h"
#include "processes.h"
#include "probe.h"
#include "log.h"

/* Removes cnx from probing list */
void remove_probing_cnx(struct loop_info* fd_info, struct connection* cnx)
{
    gap_remove_ptr(fd_info->probing_list, cnx, fd_info->num_probing);
    fd_info->num_probing--;
}

void add_probing_cnx(struct loop_info* fd_info, struct connection* cnx)
{
    gap_set(fd_info->probing_list, fd_info->num_probing, cnx);
    fd_info->num_probing++;
}

/* Returns the queue index that contains the specified file descriptor */
static int active_queue(struct connection* cnx, int fd)
{
    if (cnx->q[0].fd == fd) return 0;
    if (cnx->q[1].fd == fd) return 1;

    print_message(msg_int_error, "file descriptor %d not found in connection object\n", fd);
    return -1;
}

int tidy_connection(struct connection *cnx, struct loop_info* fd_info)
{
    int i;

    for (i = 0; i < 2; i++) {
        if (cnx->q[i].fd != -1) {
            print_message(msg_fd, "closing fd %d\n", cnx->q[i].fd);

            watchers_del_read(fd_info->watchers, cnx->q[i].fd);
            watchers_del_write(fd_info->watchers, cnx->q[i].fd);
            close(cnx->q[i].fd);
            if (cnx->q[i].deferred_data)
                free(cnx->q[i].deferred_data);
        }
    }
    collection_remove_cnx(fd_info->collection, cnx);
    return 0;
}


/* shovels data from active fd to the other
   returns after one socket closed or operation would block
 */
static void shovel(struct connection *cnx, int active_fd, struct loop_info* fd_info)
{
    struct queue *read_q, *write_q;

    read_q = &cnx->q[active_fd];
    write_q = &cnx->q[1-active_fd];

    print_message(msg_fd, "activity on fd%d\n", read_q->fd);

    switch(fd2fd(write_q, read_q)) {
    case -1:
    case FD_CNXCLOSED:
        tidy_connection(cnx, fd_info);
        break;

    case FD_STALLED:
        watchers_add_write(fd_info->watchers, write_q->fd);
        watchers_del_read(fd_info->watchers, read_q->fd);
        break;

    default: /* Nothing */
        break;
    }
}


/* Process a connection that is active in read */
static void tcp_read_process(struct loop_info* fd_info,
                             int fd)
{
    cnx_collection* collection = fd_info->collection;
    struct connection* cnx = collection_get_cnx_from_fd(collection, fd);
    /* Determine active queue (0 or 1): if fd is that of q[1], active_q = 1,
     * otherwise it's 0 */
    int active_q = active_queue(cnx, fd);

    switch (cnx->state) {

    case ST_PROBING:
        if (active_q == 1) {
            print_message(msg_int_error, "Activity on fd2 while probing, impossible\n");
            dump_connection(cnx);
            exit(1);
        }

        probing_read_process(cnx, fd_info);

        break;

    case ST_SHOVELING:
        shovel(cnx, active_q, fd_info);
        break;

    default: /* illegal */
        print_message(msg_int_error, "Illegal connection state %d\n", cnx->state);
        dump_connection(cnx);
        exit(1);
    }
}


void cnx_read_process(struct loop_info* fd_info, int fd)
{
    cnx_collection* collection = fd_info->collection;
    struct connection* cnx = collection_get_cnx_from_fd(collection, fd);
    switch (cnx->type)  {
    case SOCK_STREAM:
        tcp_read_process(fd_info, fd);
        break;

    case SOCK_DGRAM:
        udp_s2c_forward(cnx);
        break;

    default:
        print_message(msg_int_error, "cnx_read_process: Illegal connection type %d\n", cnx->type);
        dump_connection(cnx);
        exit(1);
    }
}


/* Process a connection that is active in write */
void cnx_write_process(struct loop_info* fd_info, int fd)
{
    struct connection* cnx = collection_get_cnx_from_fd(fd_info->collection, fd);
    int res;
    int queue = active_queue(cnx, fd);

    res = flush_deferred(&cnx->q[queue]);
    if ((res == -1) && ((errno == EPIPE) || (errno == ECONNRESET))) {
        if (cnx->state == ST_PROBING) remove_probing_cnx(fd_info, cnx);
        tidy_connection(cnx, fd_info);
    } else {
        /* If no deferred data is left, stop monitoring the fd 
         * for write, and restart monitoring the other one for reads*/
        if (!cnx->q[queue].deferred_data_size) {
            watchers_del_write(fd_info->watchers, cnx->q[queue].fd);
            watchers_add_read(fd_info->watchers, cnx->q[1-queue].fd);
        }
    }
}

/* Accepts a connection from the main socket and assigns it to an empty slot.
 * If no slots are available, allocate another few. If that fails, drop the
 * connexion */
static struct connection* accept_new_connection(int listen_socket, struct cnx_collection *collection)
{
    int in_socket, res;


    print_message(msg_fd, "accepting from %d\n", listen_socket);

    in_socket = accept(listen_socket, 0, 0);
    CHECK_RES_RETURN(in_socket, "accept", NULL);

    res = set_nonblock(in_socket);
    if (res == -1) {
        close(in_socket);
        return NULL;
    }

    struct connection* cnx = collection_alloc_cnx_from_fd(collection, in_socket);
    if (!cnx) {
        close(in_socket);
        return NULL;
    }

    return cnx;
}

/* Process a connection that accepts a socket
 * (For UDP, this means all traffic coming from remote clients)
 * Returns new file descriptor, or -1
 * */
int cnx_accept_process(struct loop_info* fd_info, struct listen_endpoint* listen_socket)
{
    int fd = listen_socket->socketfd;
    int type = listen_socket->type;
    struct connection* cnx;
    int new_fd = -1;

    switch (type) {
    case SOCK_STREAM:
        cnx = accept_new_connection(fd, fd_info->collection);

        if (!cnx) return -1;

        add_probing_cnx(fd_info, cnx);
        new_fd = cnx->q[0].fd;
        break;

    case SOCK_DGRAM:
        new_fd = udp_c2s_forward(fd, fd_info);
        print_message(msg_fd, "new_fd %d\n", new_fd);
        if (new_fd == -1)
            return -1;
        break;

    default:
        print_message(msg_int_error, "Inconsistent cnx type: %d\n", type);
        exit(1);
    }

    watchers_add_read(fd_info->watchers, new_fd);
    return new_fd;
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
                  print_message(msg_fd, "%s socket closed\n", i ? "server" : "client");
                  return;
              }
          }
          if (FD_ISSET(cnx->q[i].fd, &fds_r)) {
              res = fd2fd(&cnx->q[1-i], &cnx->q[i]);
              if (!res) {
                  print_message(msg_fd, "socket closed\n");
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
    out_socket = connect_addr(cnx, in_socket, BLOCKING);
    CHECK_RES_DIE(out_socket, "connect");

    cnx->q[1].fd = out_socket;

    log_connection(NULL, cnx);

    shovel_single(cnx);

    close(in_socket);
    close(out_socket);

    print_message(msg_fd, "connection closed down\n");

    exit(0);
}


/* Connect queue 1 of connection to SSL; returns new file descriptor */
static int connect_queue(struct connection* cnx,
                         struct loop_info* fd_info)
{
    struct queue *q = &cnx->q[1];

    q->fd = connect_addr(cnx, cnx->q[0].fd, NON_BLOCKING);
    if (q->fd != -1) {
        log_connection(NULL, cnx);
        flush_deferred(q);
        if (q->deferred_data) {
            /*
            FD_SET(q->fd, &fd_info->watchers->fds_w);
            FD_CLR(cnx->q[0].fd, &fd_info->watchers->fds_r); */
            watchers_add_write(fd_info->watchers, q->fd);
            watchers_del_read(fd_info->watchers, cnx->q[0].fd);
        }
        /* FD_SET(q->fd, &fd_info->watchers->fds_r); */
        watchers_add_read(fd_info->watchers, q->fd);
        collection_add_fd(fd_info->collection, cnx, q->fd);
        return q->fd;
    } else {
        tidy_connection(cnx, fd_info);
        return -1;
    }
}


/* Process read activity on a socket in probe state 
 * IN/OUT cnx: connection data, updated if connected
 * IN/OUT info: updated if connected
 * */
void probing_read_process(struct connection* cnx,
                                 struct loop_info* fd_info)
{
    int res;

    /* If timed out it's SSH, otherwise the client sent
     * data so probe the protocol */
    if ((cnx->probe_timeout < time(NULL))) {
        cnx->proto = timeout_protocol();
        print_message(msg_fd, "timed out, connect to %s\n", cnx->proto->name);
    } else {
        res = probe_client_protocol(cnx);
        if (res == PROBE_AGAIN)
            return;
    }

    remove_probing_cnx(fd_info, cnx);
    cnx->state = ST_SHOVELING;

    /* libwrap check if required for this protocol */
    if (cnx->proto->service &&
        check_access_rights(cnx->q[0].fd, cnx->proto->service)) {
        tidy_connection(cnx, fd_info);
        res = -1;
    } else if (cnx->proto->fork) {
        switch (fork()) {
        case 0:  /* child */
            /* TODO: close all file descriptors except 2 */
            /* free(cnx); */
            connect_proxy(cnx);
            exit(0);
        case -1: print_message(msg_system_error, "fork failed: err %d: %s\n", errno, strerror(errno));
                 break;
        default: /* parent */
                 break;
        }
        tidy_connection(cnx, fd_info);
        res = -1;
    } else {
        res = connect_queue(cnx, fd_info);
    }
}

