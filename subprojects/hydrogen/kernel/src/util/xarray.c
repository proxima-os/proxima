#include "util/xarray.h"
#include "hydrogen/error.h"
#include "mem/vheap.h"
#include "string.h"
#include <stdbool.h>

#define LEVEL_SHIFT 6 // 64 entries per level
#define LEVEL_COUNT (1ul << LEVEL_SHIFT)
#define LEVEL_MASK (LEVEL_COUNT - 1)
#define LEVEL_SIZE (LEVEL_COUNT * sizeof(void *))

static void **get_elem_ptr(xarray_t *arr, size_t index, bool alloc) {
    while (arr->levels == 0 || ((index >> (arr->levels * LEVEL_SHIFT)) & ~LEVEL_MASK)) {
        if (!alloc) return NULL;

        void **table = vmalloc(LEVEL_SIZE);
        if (!table) return NULL;
        memset(table, 0, LEVEL_SIZE);

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
            ptr = vmalloc(LEVEL_SIZE);
            if (!ptr) return NULL;
            memset(ptr, 0, LEVEL_SIZE);
            table[idx] = ptr;
        }

        table = ptr;
    }

    return &table[index & LEVEL_MASK];
}

static void do_clear(
        void **table,
        int level,
        void (*entry_handler)(void *, void *),
        void *ctx,
        size_t start,
        bool free
) {
    for (size_t i = start; i < LEVEL_COUNT; i++) {
        void *ptr = table[i];
        if (!ptr) continue;

        if (level == 0) {
            entry_handler(ptr, ctx);
        } else {
            do_clear(ptr, level - 1, entry_handler, ctx, 0, true);
        }

        if (!free) table[i] = NULL;
    }

    if (free) vmfree(table, LEVEL_SIZE);
}

void xarray_clear(xarray_t *arr, void (*entry_handler)(void *, void *), void *ctx) {
    if (arr->levels != 0) {
        do_clear(arr->data, arr->levels - 1, entry_handler, ctx, 0, true);
        arr->data = NULL;
        arr->levels = 0;
    }
}

void xarray_trunc(xarray_t *arr, size_t max_idx, void (*entry_handler)(void *, void *), void *ctx) {
    if (max_idx == 0) {
        xarray_clear(arr, entry_handler, ctx);
        return;
    }

    int levels = ((64 - __builtin_clzl(max_idx)) + (LEVEL_SHIFT - 1)) / LEVEL_SHIFT;

    while (arr->levels > levels) {
        void **ndata = arr->data[0];
        do_clear(arr->data, arr->levels - 1, entry_handler, ctx, 1, true);
        arr->data = ndata;
        arr->levels -= 1;
    }

    if (arr->levels < levels) return;

    size_t max_top_idx = ((max_idx - 1) >> ((levels - 1) * LEVEL_SHIFT)) + 1;
    do_clear(arr->data, arr->levels - 1, entry_handler, ctx, max_top_idx, false);
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
            return ERR_ALREADY_EXISTS;
        }
    } else {
        return ERR_OUT_OF_MEMORY;
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
        return wanted != NULL ? ERR_OUT_OF_MEMORY : 0;
    }
}
