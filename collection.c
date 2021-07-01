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
#include "gap.h"

/* Info to keep track of all connections */
struct cnx_collection {
    gap_array* fd2cnx;  /* Array indexed by file descriptor to things in cnx[] */
};

/* Allocates and initialises a new collection of connections. */
cnx_collection* collection_init(void)
{
    cnx_collection* collection;

    collection = malloc(sizeof(*collection));
    CHECK_ALLOC(collection, "collection_init(collection)");

    memset(collection, 0, sizeof(*collection));

    collection->fd2cnx = gap_init();

    return collection;
}

/* Caveat: might not work, as has never been used */
void collection_destroy(cnx_collection* collection)
{
    /* Caveat 2: no code to free connections yet */
    gap_destroy(collection->fd2cnx);
    free(collection);
}

/* Points the file descriptor to the specified connection index */
int collection_add_fd(cnx_collection* collection, struct connection* cnx, int fd)
{
    gap_set(collection->fd2cnx, fd, cnx);
    return 0;
}

/* Allocates a connection and inits it with specified file descriptor */
struct connection* collection_alloc_cnx_from_fd(struct cnx_collection* collection, int fd)
{
    struct connection* cnx = malloc(sizeof(*cnx));

    if (!cnx) return NULL;

    init_cnx(cnx);
    cnx->type = SOCK_STREAM;
    cnx->q[0].fd = fd;
    cnx->state = ST_PROBING;
    cnx->probe_timeout = time(NULL) + cfg.timeout;

    gap_set(collection->fd2cnx, fd, cnx);

    return cnx;
}

/* Remove a connection from the collection */
int collection_remove_cnx(cnx_collection* collection, struct connection *cnx)
{
    if (cnx->q[0].fd != -1)
        gap_set(collection->fd2cnx, cnx->q[0].fd, NULL);
    if (cnx->q[1].fd != -1)
        gap_set(collection->fd2cnx, cnx->q[1].fd, NULL);
    free(cnx);
    return 0;
}

/* Returns the connection that contains the file descriptor */
struct connection* collection_get_cnx_from_fd(struct cnx_collection* collection, int fd)
{
    return gap_get(collection->fd2cnx, fd);
}

