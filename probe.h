/* API for probe.c */

#ifndef PROBE_H
#define PROBE_H

#include "common.h"
#include "tls.h"

typedef enum {
    PROBE_NEXT,  /* Enough data, probe failed -- it's some other protocol */
    PROBE_MATCH, /* Enough data, probe successful -- it's the current protocol */
    PROBE_AGAIN, /* Not enough data for this probe, try again with more data */
} probe_result;

struct sslhcfg_protocols_item;
typedef int T_PROBE(const char*, ssize_t, struct sslhcfg_protocols_item*);

struct protocol_probe_desc {
    const char* name;
    T_PROBE* probe;
};


#include "sslh-conf.h"

/* Returns a pointer to the array of builtin protocols */
struct protocol_probe_desc* get_builtins(void);

/* Returns the number of builtin protocols */
int get_num_builtins(void);

/* Returns the probe for specified protocol */
T_PROBE* get_probe(const char* description);

/* Returns the head of the configured protocols */
struct sslhcfg_protocols_item* get_first_protocol(void);

/* Set the list of configured protocols */
void set_protocol_list(struct sslhcfg_protocols_item*);

/* probe_client_protocol
 *
 * Read the beginning of data coming from the client connection and check if
 * it's a known protocol. Then leave the data on the deferred
 * write buffer of the connection and returns a pointer to the protocol
 * structure
 */
int probe_client_protocol(struct connection *cnx);

/* Probe, but on a buffer */
int probe_buffer(char* buf, int len, struct sslhcfg_protocols_item** proto);

/* set the protocol to connect to in case of timeout */
void set_ontimeout(const char* name);

/* timeout_protocol
 *
 * Returns the protocol to connect to in case of timeout
 */
struct sslhcfg_protocols_item* timeout_protocol(void);

void hexdump(const char*, unsigned int);

#endif
