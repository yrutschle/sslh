#ifndef PROCESSES_H
#define PROCESSES_H

#include "common.h"
#include "collection.h"
#include "gap.h"

/* Provided by event loop, sslh-ev or sslh-select, for implementation-dependant
 * data */
typedef struct watchers watchers; 

typedef void hash;

/* Global state for a loop */
struct loop_info {
    int num_probing;     /* Number of connections currently probing 
                          * We use this to know if we need to time out of
                          * select() */
    gap_array* probing_list;  /* Pointers to cnx that are in probing mode */

    hash* hash_sources; /* UDP remote sources previously encountered */

    hash* pid2proto; /* to follow which forked PID is processing what protocol for connection count */

    watchers* watchers;
    int num_addr_listen;  /* How many listen endpoints do we have here */

    cnx_collection* collection; /* Collection of connections linked to this loop */
};

void cnx_read_process(struct loop_info* fd_info, int fd);
struct connection* cnx_accept_process(struct loop_info* fd_info, struct listen_endpoint* listen_socket);

int tidy_connection(struct connection *cnx, struct loop_info* fd_info);
void loop_init(struct loop_info* loop, int num_addr_listen);

void remember_child_data(struct loop_info* fd_info, 
                         struct connection* cnx, pid_t pid);
void decrease_forked_connection(struct loop_info* loop, pid_t pid);

/* These must be declared in the loop handler, sslh-ev or sslh-select */
void watchers_add_read(watchers* w, int fd);
void watchers_del_read(watchers* w, int fd);
void watchers_add_write(watchers* w, int fd);
void watchers_del_write(watchers* w, int fd);

void watcher_sigchld(struct loop_info* fd_info, struct connection* cnx, pid_t pid);

#endif
