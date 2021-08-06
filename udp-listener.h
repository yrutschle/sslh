#ifndef UDPLISTENER_H
#define UDPLISTENER_H

#include "collection.h"

/* UDP listener: upon incoming packet, find where it should go
 * This is run in its own process and never returns.
 */
void udp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint);


/* Process UDP coming from outside (client towards server)
 * If it's a new source, probe; otherwise, forward to previous target 
 * Returns: >= 0 sockfd of newly allocated socket, for new connections
 * -1 otherwise
 * */
int udp_c2s_forward(int sockfd, cnx_collection* collection, int max_fd);

/* Process UDP coming from inside (server towards client) */
void udp_s2c_forward(struct connection* cnx);


/* returns how many seconds before socket times out. Negative if timed out
 * already.
 */
int udp_timeout(struct connection* cnx);

#endif /* UDPLISTENER_H */
