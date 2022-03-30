

typedef struct hash hash;
typedef struct hash_item* hash_item;
typedef int (*hash_make_key_fn)(hash_item item);

/* Function that compares two items: returns 0 if they are the same */
typedef int (*hash_cmp_item_fn)(hash_item item1, hash_item item2);

hash* hash_init(hash_make_key_fn make_key, hash_cmp_item_fn cmp_item);
int hash_find_index(hash* h, hash_item item);
int hash_insert(hash* h, hash_item new);
int hash_remove(hash* h, hash_item item);


void hash_dump(hash* h, char* filename); /* For development only */
