#ifndef TCP_LISTENER_H
#define TCP_LISTENER_H

#include "processes.h"
#include "collection.h"
#include "tcp-probe.h"

void tcp_read_process(struct loop_info* fd_info, int fd);
struct connection* accept_new_connection(int listen_socket, struct loop_info* fd_info);
void probing_read_process(struct connection* cnx, struct loop_info* fd_info);
void cnx_write_process(struct loop_info* fd_info, int fd);

#endif
