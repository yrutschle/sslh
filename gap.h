#ifndef GAP_H
#define GAP_H

typedef struct gap_array gap_array;

gap_array* gap_init(int len);
void gap_set_hardlimit(gap_array* ga, int index);
static void* gap_get(gap_array* gap, int index);
static int gap_set(gap_array* gap, int index, void* ptr);
void gap_destroy(gap_array* gap);

int gap_remove_ptr(gap_array* gap, void* ptr, int len);

/* Private declarations to allow inlining.
 * Don't assume my implementation. */
typedef struct gap_array {
    int len; /* Number of elements in array (corresponds to the number of pages allocated) */
    int hardlimit; /* Maximum index allowed after which sets will fail; 0 means no limit */
    void** array;
} gap_array;

int gap_extend(gap_array* gap);

static inline int __attribute__((unused)) gap_set(gap_array* gap, int index, void* ptr)
{
    if (gap->hardlimit && (index > gap->hardlimit))
        return -1;

    while (index >= gap->len) {
        int res = gap_extend(gap);
        if (res == -1) return -1;
    }

    gap->array[index] = ptr;
    return 0;
}

static inline void* __attribute__((unused)) gap_get(gap_array* gap, int index)
{
    /* sslh-ev routinely reads before it writes. It's not clear if it should be
     * its job to check the length (and add a gap_getlen()), or if it should be
     * gap_get()'s job. This will do for now */
    if (index >= gap->len) return NULL;

    if (gap->hardlimit && (index > gap->hardlimit)) return NULL;

    return gap->array[index];
}

#endif
