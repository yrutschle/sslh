/* API for probe.c */

#ifndef __PROBE_H_
#define __PROBE_H_

#include "common.h"

struct proto;
typedef int T_PROBE(const char*, int, struct proto*);

/* For each protocol we need: */
struct proto {
    const char* description;  /* a string that says what it is (for logging and command-line parsing) */
    const char* service;      /* service name to do libwrap checks */
    struct addrinfo *saddr; /* list of addresses to try and switch that protocol */

    /* function to probe that protocol; parameters are buffer and length
     * containing the data to probe, and a pointer to the protocol structure */
    T_PROBE* probe;
    void* data;     /* opaque pointer ; used to pass list of regex to regex probe */
    struct proto *next; /* pointer to next protocol in list, NULL if last */
};

/* Returns a pointer to the array of builtin protocols */
struct proto * get_builtins(void);

/* Returns the number of builtin protocols */
int get_num_builtins(void);

/* Returns the probe for specified protocol */
T_PROBE* get_probe(const char* description);

/* Returns the head of the configured protocols */
struct proto* get_first_protocol(void);

/* Set the list of configured protocols */
void set_protocol_list(struct proto*);

/* probe_client_protocol
 *
 * Read the beginning of data coming from the client connection and check if
 * it's a known protocol. Then leave the data on the defered
 * write buffer of the connection and returns a pointer to the protocol
 * structure
 */
struct proto* probe_client_protocol(struct connection *cnx);

/* set the protocol to connect to in case of timeout */
void set_ontimeout(const char* name);

/* timeout_protocol
 *
 * Returns the protocol to connect to in case of timeout
 */
struct proto* timeout_protocol(void);

void hexdump(const char*, unsigned int);

#endif
