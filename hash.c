/* 
 * a fixed-sized hash
 *
# Copyright (C) 2022  Yves Rutschle
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
#
# */


/*  * The hash is open-addressing, linear search, robin-hood insertion, with 
 * backward shift deletion and moving floor.
 * https://codecapsule.com/2013/11/11/robin-hood-hashing/
 * https://codecapsule.com/2013/11/17/robin-hood-hashing-backward-shift-deletion/
 * This means items are reordered upon insertion and deletion, and the hash
 * is well-ordered at all times with no tombstones.
 *
 * Items that 'wrap' around push the 'floor' up. Searching for low items will
 * therefore start from the floor up.
 *
 * Each pointer is either:
 * - to a connection struct
 * - FREE (NULL) if not allocated
 *
 * */

#include <stdlib.h>
#include <stddef.h>

#include "gap.h"

typedef void* hash_item;
#include "hash.h"

static const int h_keylen = 5; /* How many bits in the hash key? (hash is 2^h_keylen big) */
static const int hash_size = (1 << h_keylen); /* 8 => 256 */
static const int keymask = hash_size - 1;  /* 8 => 11111111 */
static void* const FREE = NULL;

struct hash {
    int item_cnt;       /* Number of items in the hash */
    int floor;          /* Where is the highest key. Or the lowest insert point */
    gap_array* data;

    hash_make_key_fn hash_make_key;
    hash_cmp_item_fn cmp_item;
};

typedef struct hash hash;


static int hash_make_key(hash* h, hash_item item)
{
    return h->hash_make_key(item) & keymask;
}


hash* hash_init(hash_make_key_fn make_key, hash_cmp_item_fn cmp_item)
{
    hash* h = malloc(sizeof(*h));
    if (!h) return NULL;

    h->item_cnt = 0;
    h->floor = 0;
    h->data = gap_init(hash_size);
    h->hash_make_key = make_key;
    h->cmp_item = cmp_item;

    return h;
}

/* Return the index following i in h */
static int hash_next_index(hash* h, int i)
{
    return (i + 1) % hash_size;
}

/* Returns the index in h of specified address, -1 if not found 
 * item is an item object that must return the target wanted index and for
 * which comparison with the searched object will succeed.
 * */
static int hash_find_index(hash* h, hash_item item)
{
    hash_item cnx;
    int index = hash_make_key(h, item);
    int cnt = 0;

    if (index < h->floor) index = h->floor;

    cnx = gap_get(h->data, index);
#ifdef DEBUG
    fprintf(stderr, "searching %d\n", index);
#endif
    while (cnx != FREE) {
        if (cnt++ > hash_size) return -1;

        if (!h->cmp_item(cnx, item))
            break;

        index = hash_next_index(h, index);
        cnx = gap_get(h->data, index);
#ifdef DEBUG
        fprintf(stderr, "searching %d\n", index);
#endif
    } 
    if (cnx == FREE) return -1;
    return index;
}

hash_item hash_find(hash* h, hash_item item)
{
    int index = hash_find_index(h, item);
    if (index == -1) return NULL;
    hash_item out = gap_get(h->data, index);
    return out;
}


/* Returns DIB: distance to initial bucket */
static int distance(int actual_index, hash* h, hash_item item)
{
    int wanted_index = hash_make_key(h, item);
    if (wanted_index <= actual_index)
        return wanted_index - actual_index;
    else
        return wanted_index + hash_size - actual_index;
}


int hash_insert(hash* h, hash_item new)
{
    int bubble_wanted_index = hash_make_key(h, new);
    int index = bubble_wanted_index;
    gap_array* hash = h->data;

    if (h->item_cnt == hash_size)
        return -1;

    if (index < h->floor) index = h->floor;

    hash_item curr_item = gap_get(hash, index);
    while (curr_item) {
        if (distance(index, h, curr_item) > distance(index, h, new)) {
            gap_set(h->data, index, new);
#if DEBUG
            fprintf(stderr, "intermediate insert [%s] at %d\n", &new->client_addr, index);
#endif
            new = curr_item;
        }

        index = hash_next_index(h, index);
        curr_item = gap_get(hash, index);

        if (index == 0) h->floor++;
    }

#if DEBUG
    fprintf(stderr, "final insert at %d\n", index);
#endif
    gap_set(hash, index, new);
    h->item_cnt++;

    return 0;
}

/* Remove cnx from the hash */
int hash_remove(hash* h, hash_item item)
{
    gap_array* hash = h->data;

    int index = hash_find_index(h, item);
    if (index == -1) return -1; /* Tried to remove something that isn't there */

    int lower_floor = 0; /* If we remove something below the floor, we'll need to lower it */
    while (1) {
        if (index < h->floor) lower_floor = 1;
        int next_index = hash_next_index(h, index);
        hash_item next = gap_get(h->data, next_index);
        if ((next == FREE) || (distance(next_index, h, next) == 0)) {
            h->item_cnt--;
            if (lower_floor) h->floor--;
            gap_set(hash, index, FREE);
            return 0;
        }

        gap_set(hash, index, next);

        index = hash_next_index(h, index);;
#if DEBUG
        fprintf(stderr, "index %d floor %d\n", index, h->floor);
#endif
    }
    return 0;
}

#if HASH_TESTING
#include <stdio.h>
#include <string.h>
#define STR_LENGTH 16
struct hash_item {
    int wanted_index;
    char str[STR_LENGTH];
};
void hash_dump(hash* h, char* filename)
{
    char str[STR_LENGTH];
    FILE* out = fopen(filename, "w");

    if (!out) {
        perror(filename);
        exit(1);
    }
    
    fprintf(out, "<hash floor=%d elem=%d>\n", h->floor, h->item_cnt);
    for (int i = 0; i < hash_size; i++) {
        hash_item item = gap_get(h->data, i);
        int idx = 0;

        memset(str, 0, STR_LENGTH);
        if (item) {
            idx = hash_make_key(h, item);
            memcpy(str, ((struct hash_item*)item)->str, STR_LENGTH);
        }
        fprintf(out, "\t%d:%d:%s\n", i, idx, str);
    }
    fprintf(out, "</hash>\n");
    fclose(out);
}
#endif
