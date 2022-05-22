#ifndef UDPLISTENER_H
#define UDPLISTENER_H


#include "collection.h"
#include "processes.h"
#include "common.h"

/* UDP listener: upon incoming packet, find where it should go
 * This is run in its own process and never returns.
 */
void udp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint);


/* Process UDP coming from outside (client towards server)
 * If it's a new source, probe; otherwise, forward to previous target 
 * Returns: newly allocate connections, for new connections
 * -1 otherwise
 * */
struct connection* udp_c2s_forward(int sockfd, struct loop_info* fd_info);

/* Process UDP coming from inside (server towards client) */
void udp_s2c_forward(struct connection* cnx);


void udp_init(struct loop_info* fd_info);
void udp_tidy(struct connection* cnx, struct loop_info* fd_info);

#endif /* UDPLISTENER_H */
