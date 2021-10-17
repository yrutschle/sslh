#ifndef PROCESSES_H
#define PROCESSES_H

#ifndef WATCHERS_TYPE_DEFINED
#error Define watchers type before including processes.h
#endif

#include "common.h"
#include "collection.h"
#include "gap.h"


/* Global state for a loop */
struct loop_info {
    int num_probing;     /* Number of connections currently probing 
                          * We use this to know if we need to time out of
                          * select() */
    gap_array* probing_list;  /* Pointers to cnx that are in probing mode */

    watchers watchers;

    cnx_collection* collection; /* Collection of connections linked to this loop */

    time_t next_timeout; /* time at which next UDP connection times out */
};

void cnx_read_process(struct loop_info* fd_info, int fd);
void cnx_write_process(struct loop_info* fd_info, int fd);
void cnx_accept_process(struct loop_info* fd_info, struct listen_endpoint* listen_socket);
void probing_read_process(struct connection* cnx, struct loop_info* fd_info);

void remove_probing_cnx(struct loop_info* fd_info, struct connection* cnx);
void add_probing_cnx(struct loop_info* fd_info, struct connection* cnx);

#endif
