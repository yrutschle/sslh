#ifndef GAP_H
#define GAP_H

typedef struct gap_array gap_array;

gap_array* gap_init();
void* gap_get(gap_array* gap, int index);
int gap_set(gap_array* gap, int index, void* ptr);
void gap_destroy(gap_array* gap);

int gap_remove_ptr(gap_array* gap, void* ptr, int len);

#endif
