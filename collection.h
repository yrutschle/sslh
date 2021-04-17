#ifndef COLLECTION_H
#define COLLECTION_H

typedef struct cnx_collection cnx_collection;


cnx_collection* collection_init(void);
void collection_destroy(cnx_collection* collection);

struct connection* collection_alloc_cnx_from_fd(cnx_collection* collection, int fd);
int collection_add_fd(cnx_collection* collection, struct connection* cnx, int fd);

/* Remove a connection from the collection */
int collection_remove_cnx(cnx_collection* collection, struct connection *cnx);

struct connection* collection_get_cnx_from_fd(struct cnx_collection* collection, int fd);

#endif
