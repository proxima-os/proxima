#ifndef HYDROGEN_UTIL_XARRAY_H
#define HYDROGEN_UTIL_XARRAY_H

#include <stddef.h>

typedef struct {
    void **data;
    int levels;
} xarray_t;

// Clears the array, freeing all data associated with it
void xarray_clear(xarray_t *arr, void (*entry_handler)(void *, void *), void *ctx);

void xarray_trunc(xarray_t *arr, size_t max_idx, void (*entry_handler)(void *, void *), void *ctx);

// Returns the value at index, or NULL if the index is invalid
void *xarray_get(xarray_t *arr, size_t index);

// Inserts value at index. Returns ERR_OUT_OF_MEMORY if out of memory and ERR_ALREADY_EXISTS if the index is in use.
int xarray_put(xarray_t *arr, size_t index, void *value);

// Replaces the value at index with *value, and writes the old value to *value.
// Returns ERR_OUT_OF_MEMORY if out of memory. If *value is NULL, this is always successful.
int xarray_replace(xarray_t *arr, size_t index, void **value);

// Removes the value at index and returns it
static inline void *xarray_remove(xarray_t *arr, size_t index) {
    void *element = NULL;
    xarray_replace(arr, index, &element);
    return element;
}

#endif // HYDROGEN_UTIL_XARRAY_H
