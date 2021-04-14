#ifndef GAP_H
#define GAP_H

typedef struct gap_array gap_array;

gap_array* gap_init();
int gap_getlen(gap_array* gap);
void* gap_get(gap_array* gap, int index);
int gap_set(gap_array* gap, int index, void* ptr);
void gap_destroy(gap_array* gap);

#endif
