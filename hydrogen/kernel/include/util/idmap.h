#ifndef HYDROGEN_UTIL_IDMAP_H
#define HYDROGEN_UTIL_IDMAP_H

#include "util/xarray.h"
#include <stdbool.h>

typedef struct {
    xarray_t elements;
    int search_start;
} idmap_t;

void *idmap_get(idmap_t *map, int id);

// Allocates an ID and associates it with value. On error returns the negative error code. Possible errors are
// -ERR_OUT_OF_MEMORY and -ERR_BUSY. The allocated ID is guaranteed to be the lowest available.
int idmap_alloc(idmap_t *map, void *value);

// Frees the given ID and returns the value it was associated with.
void *idmap_free(idmap_t *map, int id);

#endif // HYDROGEN_UTIL_IDMAP_H
