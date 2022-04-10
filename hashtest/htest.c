/* Wee testing program from the hash code:
 * htest <script> <dump>
 *
 * scripts are a list of operations:
 * a $index $string
 * => add an element at specified index
 * d $index $string
 * => remove an element
 * s $index $string
 * => prints the actual element index, if it's there
 *
 * The hash is dumped to the dump file at each iteration.
 */


#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


/* tests have been written for a hash that holds 32 items */
#define HASH_SIZE 32

#define STR_LENGTH 16
struct hash_item {
    int wanted_index;
    char str[STR_LENGTH];
};

typedef struct hash_item* hash_item;

#include "../hash.h"



static int cmp_item(hash_item item1, hash_item item2)
{
    return strcmp(item1->str, item2->str);
}


static int hash_make_key(hash_item item)
{
    return item->wanted_index;
}


static void htest_next_key(FILE* f, char* action, int* key, char str[STR_LENGTH])
{

    int res = 0;
    while ((res != 3) && (res != EOF))
        res = fscanf(f, "%c %d %s\n", action, key, str);
    if (res == EOF) exit(0);
}

int main(int argc, char* argv[])
{
    hash* h = hash_init(HASH_SIZE, &hash_make_key, &cmp_item);
    char action;
    hash_item item;
    int line = 0;
    FILE* f;

    if (argc != 3) {
        fprintf(stderr, "Usage: htest <script file> <dump file>\n");
        exit(1);
    }
    char* script_file = argv[1];
    char* dump_file = argv[2];
    f = fopen(argv[1], "r");
    if (!f) {
        perror(script_file);
        exit(1);
    }

    while (1) {
        item= malloc(sizeof(*item));
        action = ' ';

        line++;
        htest_next_key(f, &action, &item->wanted_index, item->str);
        fprintf(stderr, "action %d: %c %d %s\n", line, action, item->wanted_index, item->str);

        switch (action) {
        case 'a': /* add */
            fprintf(stderr, "inserting [%s] at %d\n", item->str, item->wanted_index);
            hash_insert(h, item);
            break;

        case 'd': /* del */
            fprintf(stderr, "removing [%s] at %d\n", item->str, item->wanted_index);
            hash_remove(h, item);
            break;

        case 's': /* search */
            fprintf(stderr, "searching\n");
            struct hash_item* found = hash_find(h, item);
            fprintf(stderr, "searching %d[%s]: %p\n", item->wanted_index, item->str, found);
            break;

        case 'q': /* quit */
            exit(1);
        }
        hash_dump(h, dump_file);
    }
    return 0;
}
