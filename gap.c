/*
   gap.c: gap, a simple, dynamically-growing array
   of pointers that never shrinks

# Copyright (C) 2021  Yves Rutschle
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

*/


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gap.h"


typedef struct gap_array {
    int len; /* Number of elements in array */
    void** array;
} gap_array;

/* Allocate one page-worth of elements */
static int gap_len_alloc(int elem_size)
{
    return getpagesize() / elem_size;
}

/* Creates a new gap, all pointers are initialised at NULL */
gap_array* gap_init(void)
{
    gap_array* gap = malloc(sizeof(*gap));
    if (!gap) return NULL;
    memset(gap, 0, sizeof(*gap));

    int elem_size = sizeof(gap->array[0]);
    gap->len = gap_len_alloc(elem_size);
    gap->array = malloc(gap->len * elem_size);
    if (!gap->array) return NULL;

    for (int i = 0; i < gap->len; i++)
        gap->array[i] = NULL;

    return gap;
}

int gap_getlen(gap_array* gap)
{
    return gap->len;
}

void* gap_get(gap_array* gap, int index)
{
    int elem_size = sizeof(gap->array[0]);
    return gap->array[index * elem_size];
}

static int gap_extend(gap_array* gap)
{
    int elem_size = sizeof(gap->array[0]);
    int new_length = gap->len + gap_len_alloc(elem_size);
    void** new = realloc(gap->array, new_length * elem_size);
    if (!new) return -1;

    for (int i = gap->len; i < new_length; i++)
        gap->array[i] = NULL;
    return 0;
}

int gap_set(gap_array* gap, int index, void* ptr)
{
    if (index > gap->len) {
        int res = gap_extend(gap);
        if (res == -1) return -1;
    }

    int elem_size = sizeof(gap->array[0]);
    gap->array[index * elem_size] = ptr;
    return 0;
}

void gap_destroy(gap_array* gap) 
{
    free(gap->array);
    free(gap);
}

