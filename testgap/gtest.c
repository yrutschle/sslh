/* Wee testing program from the gap code, this is very similar to the hash
 * testing code.
 * Instead of pointers, we use integers
 *
 * script language:
 * a 5 12     # adds value 12 at index 5
 * d 512 42   # remove value 42, 512 is the length of the array
 * h 16 0     # set hard limit to 16 (value is not used)
 */


#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>



#include "../gap.h"

static void gtest_next_line(FILE* f, char* action, int* index, void** value)
{

    int res = 0;
    while ((res != 3) && (res != EOF))
        res = fscanf(f, "%c %d %p\n", action, index, value);
    if (res == EOF) exit(0);
}

static void gap_dump(gap_array* gap, char* filename)
{
    int i;
    FILE* out = fopen(filename, "w");

    if (!out) {
        perror(filename);
        exit(1);
    }

    fprintf(out, "<gap len=%d hardlimit=%d>\n", gap->len, gap->hardlimit);
    for (i = 0; i < gap->len; i++) {
        void* value = gap_get(gap, i);
        fprintf(out, "[%d] = %p\n", i, value);
    }
    fprintf(out, "</gap>\n");
    fclose(out);
}


int main(int argc, char* argv[])
{
    gap_array* gap = gap_init(0);
    char action;
    int line = 0, index;
    void* value;
    FILE* f;

    if (argc != 3) {
        fprintf(stderr, "Usage: gtest <script file> <dump file>\n");
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
        action = ' ';

        line++;
        gtest_next_line(f, &action, &index, &value);
        fprintf(stderr, "action %d: %c %d %p\n", line, action, index, value);

        switch (action) {
        case 'a': /* add */
            fprintf(stderr, "[%d] = %p\n", index, value);
            gap_set(gap, index, value);
            break;

        case 'd': /* del */
            fprintf(stderr, "removing %p\n", value);
            int res = gap_remove_ptr(gap, (void*)value, index);
            fprintf(stderr, "remove: %d\n", res);
            break;

        case 'h': /* hardlimit */
            fprintf(stderr, "setting hard limit %d\n", index);
            gap_set_hardlimit(gap, index);

        case 'g': /* get */
            fprintf(stderr, "searching\n");
            value = gap_get(gap, index);
            fprintf(stderr, "got [%d]= %p\n", index, value);
            break;
        }
        gap_dump(gap, dump_file);
    }
    return 0;
}
