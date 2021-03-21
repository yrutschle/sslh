/*
   collection.c: management of a collection of connections, for sslh-select

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

#include "common.h"
#include "collection.h"
#include "sslh-conf.h"


/* Info to keep track of all connections */
struct cnx_collection {
    int num_cnx;  /* Number of connections in *cnx */
    struct connection *cnx; /* pointer to array of connections */
};

/* cnx_num_alloc is the number of connection to allocate at once (at start-up,
 * and then every time we get too many simultaneous connections: e.g. start
 * with 100 slots, then if we get more than 100 connections allocate another
 * 100 slots, and so on). We never free up connection structures. We try to
 * allocate as many structures at once as will fit in one page (which is 102
 * in sslh 1.9 on Linux on x86)
 */
static long cnx_num_alloc;



/* Allocates and initialises a new collection of connections. */
cnx_collection* collection_init(void)
{
    int i;
    cnx_collection* collection;

    collection = malloc(sizeof(*collection));
    CHECK_ALLOC(collection, "malloc(collection)");

    memset(collection, 0, sizeof(*collection));
    cnx_num_alloc = getpagesize() / sizeof(struct connection);

    collection->num_cnx = cnx_num_alloc; /* Start with a set pool of slots */
    collection->cnx = malloc(collection->num_cnx * sizeof(struct connection));
    CHECK_ALLOC(collection->cnx, "malloc(collection->cnx)");

    for (i = 0; i < collection->num_cnx; i++) {
        init_cnx(&collection->cnx[i]);
    }
    return collection;
}

void collection_destroy(cnx_collection* collection)
{
    free(collection);
}

/* Increases the number of slots available in a collection of connections
 * After calling, collection->cnx might have moved
 * */
static int collection_extend(struct cnx_collection* collection)
{
    struct connection* new;
    int i, new_length = collection->num_cnx + cnx_num_alloc;

    if (cfg.verbose)
        fprintf(stderr, "allocating %ld more slots (target: %d).\n", cnx_num_alloc, new_length);
    new = realloc(collection->cnx, new_length * sizeof(collection->cnx[0]));
    if (!new) return -1;

    collection->cnx = new;

    for (i = collection->num_cnx; i < new_length; i++) {
        init_cnx(&collection->cnx[i]); 
    }
    collection->num_cnx = new_length;
    return 0;
}


int collection_add_fd(struct cnx_collection* collection, int fd)
{
    int free, res;
    struct connection* cnx = collection->cnx;

    /* Find an empty slot */
    for (free = 0; (free < collection->num_cnx) && (cnx[free].q[0].fd != -1); free++) {
        /* nothing */
    }
    if (free >= collection->num_cnx)  {
        res = collection_extend(collection);
        if (res) {
            log_message(LOG_ERR, "unable to extend collection -- dropping connection\n");
            return -1;
        }
    }
    collection->cnx[free].q[0].fd = fd;
    collection->cnx[free].state = ST_PROBING;
    collection->cnx[free].probe_timeout = time(NULL) + cfg.timeout;

    if (cfg.verbose) 
        fprintf(stderr, "accepted fd %d on slot %d\n", fd, free);
    return 0;
}


/* Returns the indexed connection in the collection */
struct connection* collection_get_cnx(struct cnx_collection* collection, int index)
{
    return & collection->cnx[index];
}

/* Returns the number of connections in the collection */
int collection_get_length(cnx_collection* collection)
{
    return collection->num_cnx;
}
