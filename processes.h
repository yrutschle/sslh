#ifndef PROCESSES_H
#define PROCESSES_H

#ifndef WATCHERS_TYPE_DEFINED
#error Define watchers type before including processes.h
#endif

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

#endif
