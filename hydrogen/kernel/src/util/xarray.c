#include "util/xarray.h"
#include "errno.h"
#include "mem/heap.h"
#include "string.h"
#include <stdbool.h>

#define LEVEL_SHIFT 6 // 64 entries per level
#define LEVEL_SIZE (1ul << LEVEL_SHIFT)
#define LEVEL_MASK (LEVEL_SIZE - 1)

static void **get_elem_ptr(xarray_t *arr, size_t index, bool alloc) {
    while (arr->levels == 0 || ((index >> (arr->levels * LEVEL_SHIFT)) & ~LEVEL_MASK)) {
        if (!alloc) return NULL;

        void **table = kalloc(LEVEL_SIZE * sizeof(void *));
        if (!table) return NULL;
        memset(table, 0, LEVEL_SIZE * sizeof(void *));

        table[0] = arr->data;
        arr->data = table;
        arr->levels += 1;
    }

    void **table = arr->data;

    for (int i = arr->levels - 1; i > 0; i--) {
        size_t idx = (index >> (i * LEVEL_SHIFT)) & LEVEL_MASK;
        void *ptr = table[idx];

        if (ptr == NULL) {
            if (!alloc) return NULL;
            ptr = kalloc(LEVEL_SIZE * sizeof(void *));
            if (!ptr) return NULL;
            memset(ptr, 0, LEVEL_SIZE * sizeof(void *));
            table[idx] = ptr;
        }

        table = ptr;
    }

    return &table[index & LEVEL_MASK];
}

void *xarray_get(xarray_t *arr, size_t index) {
    void **ptr = get_elem_ptr(arr, index, false);
    return ptr ? *ptr : NULL;
}

int xarray_put(xarray_t *arr, size_t index, void *value) {
    void **ptr = get_elem_ptr(arr, index, true);

    if (ptr != NULL) {
        if (*ptr == NULL) {
            *ptr = value;
            return 0;
        } else {
            return EBUSY;
        }
    } else {
        return ENOMEM;
    }
}

int xarray_replace(xarray_t *arr, size_t index, void **value) {
    void *wanted = *value;
    void **ptr = get_elem_ptr(arr, index, wanted != NULL);

    if (ptr != NULL) {
        *value = *ptr;
        *ptr = wanted;
        return 0;
    } else {
        return wanted != NULL ? ENOMEM : 0;
    }
}
