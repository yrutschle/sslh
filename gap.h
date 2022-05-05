#ifndef GAP_H
#define GAP_H

typedef struct gap_array gap_array;

gap_array* gap_init(int len);
static void* gap_get(gap_array* gap, int index);
static int gap_set(gap_array* gap, int index, void* ptr);
void gap_destroy(gap_array* gap);

int gap_remove_ptr(gap_array* gap, void* ptr, int len);

/* Private declarations to allow inlining.
 * Don't assume my implementation. */
typedef struct gap_array {
    int len; /* Number of elements in array */
    void** array;
} gap_array;

int gap_extend(gap_array* gap);

static inline int __attribute__((unused)) gap_set(gap_array* gap, int index, void* ptr)
{
    while (index >= gap->len) {
        int res = gap_extend(gap);
        if (res == -1) return -1;
    }

    gap->array[index] = ptr;
    return 0;
}

static inline void* __attribute__((unused)) gap_get(gap_array* gap, int index)
{
    return gap->array[index];
}

#endif
