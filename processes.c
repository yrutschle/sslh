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
#include "tcp-listener.h"
#include "processes.h"
#include "probe.h"
#include "log.h"


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

    if (cnx->type == SOCK_DGRAM)
        udp_tidy(cnx, fd_info);

    if (gap_remove_ptr(fd_info->probing_list, cnx, fd_info->num_probing) != -1)
        fd_info->num_probing--;

    collection_remove_cnx(fd_info->collection, cnx);
    return 0;
}



/* Process a connection that is active in read */

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


/* Process a connection that accepts a socket
 * (For UDP, this means all traffic coming from remote clients)
 * Returns new connection object, or NULL
 * */
struct connection* cnx_accept_process(struct loop_info* fd_info, struct listen_endpoint* listen_socket)
{
    int fd = listen_socket->socketfd;
    int type = listen_socket->type;
    struct connection* cnx;

    switch (type) {
    case SOCK_STREAM:
        cnx = accept_new_connection(fd, fd_info);
        if (!cnx) return NULL;

        break;

    case SOCK_DGRAM:
        cnx = udp_c2s_forward(fd, fd_info);
        if (!cnx) return NULL;
        break;

    default:
        print_message(msg_int_error, "Inconsistent cnx type: %d\n", type);
        exit(1);
    }

    int new_fd = cnx->q[0].fd;
    watchers_add_read(fd_info->watchers, new_fd);
    return cnx;
}




