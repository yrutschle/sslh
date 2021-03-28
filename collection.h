#ifndef COLLECTION_H
#define COLLECTION_H

typedef struct cnx_collection cnx_collection;


cnx_collection* collection_init(void);
void collection_destroy(cnx_collection* collection);

int collection_alloc_cnx_from_fd(cnx_collection* collection, int fd);
int collection_add_fd(cnx_collection* collection, int fd, int cnx_index);

/* Remove a connection from the collection */
int collection_remove_cnx(cnx_collection* collection, struct connection *cnx);

struct connection* collection_get_cnx(cnx_collection* collection, int index);

/* Returns the number of connections in the collection */
int collection_get_length(cnx_collection* collection);

#endif
