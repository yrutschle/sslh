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

    int num_fd; /* Number of file descriptors */
    int* fd2cnx; /* Array indexed by file descriptor to index in cnx[] */
    /* We don't try to keep the size of cnx and fd2cnx in sync at all,
     * so that the implementation is independant of other uses for file
     * descriptors, e.g. if sslh get integrated in another process */
};

/* cnx_num_alloc is the number of connection to allocate at once (at start-up,
 * and then every time we get too many simultaneous connections: e.g. start
 * with 100 slots, then if we get more than 100 connections allocate another
 * 100 slots, and so on). We never free up connection structures. We try to
 * allocate as many structures at once as will fit in one page (which is 102
 * in sslh 1.9 on Linux on x86)
 */
static long cnx_num_alloc;

static long fd_num_alloc; /* same, but for the file descriptor array */



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

    fd_num_alloc = getpagesize() / sizeof(collection->fd2cnx[0]);

    collection->num_fd = fd_num_alloc;
    collection->fd2cnx = malloc(collection->num_fd * sizeof(collection->fd2cnx[0])); 
    CHECK_ALLOC(collection->fd2cnx, "malloc(collection->fd2cnx)");

    for (i = 0; i < collection->num_fd; i++) {
        collection->fd2cnx[i] = -1;
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
static int extend_cnx(struct cnx_collection* collection)
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

static int extend_fd2cnx(cnx_collection* collection)
{
    int* new_i;
    int i, new_length;

    new_length = collection->num_fd + fd_num_alloc;

    new_i = realloc(collection->fd2cnx, new_length * sizeof(*new_i));
    if (!new_i) {
        return -1;
    }

    collection->fd2cnx = new_i;

    for (i = collection->num_fd; i < new_length; i++) {
        collection->fd2cnx[i] = -1;
    }
    collection->num_fd = new_length;

    return 0;
}

/* Points the file descriptor to the specified connection index */
int collection_add_fd(cnx_collection* collection, int fd, int cnx_index)
{
    if (fd > collection->num_fd) {
        int res = extend_fd2cnx(collection);
        if (res) {
            log_message(LOG_ERR, "unable to extend fd2cnx -- dropping connection\n");
            return -1;
        }
    }
    collection->fd2cnx[fd] = cnx_index;
    return 0;
}


/* Allocates a connection and inits it with specified file descriptor */
int collection_alloc_cnx_from_fd(struct cnx_collection* collection, int fd)
{
    int free, res;
    struct connection* cnx = collection->cnx;

    if (cfg.verbose) fprintf(stderr, "collection_add_fd %d\n", fd);

    /* Find an empty slot */
    for (free = 0; (free < collection->num_cnx) && (cnx[free].q[0].fd != -1); free++) {
        /* nothing */
    }
    if (free >= collection->num_cnx)  {
        res = extend_cnx(collection);
        if (res) {
            log_message(LOG_ERR, "unable to extend collection -- dropping connection\n");
            return -1;
        }
    }
    collection->cnx[free].q[0].fd = fd;
    collection->cnx[free].state = ST_PROBING;
    collection->cnx[free].probe_timeout = time(NULL) + cfg.timeout;

    collection_add_fd(collection, fd, free);

    if (cfg.verbose) 
        fprintf(stderr, "accepted fd %d on slot %d\n", fd, free);
    return 0;
}

/* Remove a connection from the collection */
int collection_remove_cnx(cnx_collection* collection, struct connection *cnx)
{
    collection->fd2cnx[cnx->q[0].fd] = -1;
    collection->fd2cnx[cnx->q[1].fd] = -1;
    init_cnx(cnx);
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
