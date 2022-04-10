#ifndef HASH_H
#define HASH_H

/* You will need to typedef a pointer type to hash_item before including this
 * .h */

typedef struct hash hash;

/* Function that returns a key (index) for a given item. The key must be always
 * the same for an item. It doesn't need to be bounded (hash.c masks it for you) */
typedef int (*hash_make_key_fn)(hash_item item);

/* Function that compares two items: returns 0 if they are the same */
typedef int (*hash_cmp_item_fn)(hash_item item1, hash_item item2);

hash* hash_init(int hash_size, hash_make_key_fn make_key, hash_cmp_item_fn cmp_item);

int hash_insert(hash* h, hash_item new);
int hash_remove(hash* h, hash_item item);

/* Returns the hash item that matches specification (meaning the
 * comparison function returns true for cmp(x, item), or NULL if not found */
hash_item hash_find(hash* h, hash_item item);


void hash_dump(hash* h, char* filename); /* For development only */

#endif
