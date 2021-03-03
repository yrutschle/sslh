#ifndef UDPLISTENER_H
#define UDPLISTENER_H

/* UDP listener: upon incoming packet, find where it should go
 * This is run in its own process and never returns.
 */
void udp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint);



#endif /* UDPLISTENER_H */
