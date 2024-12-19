#include "util/idmap.h"
#include "errno.h"
#include "util/xarray.h"
#include <limits.h>

void *idmap_get(idmap_t *map, int id) {
    return xarray_get(&map->elements, id);
}

int idmap_alloc(idmap_t *map, void *value) {
    for (;;) {
        int id = map->search_start;
        int error = xarray_put(&map->elements, id, value);

        if (error == 0) {
            if (id != INT_MAX) map->search_start += 1;
            return id;
        } else if (error != EBUSY) {
            return -error;
        }

        if (id == INT_MAX) return -EBUSY;
        map->search_start += 1;
    }
}

void *idmap_free(idmap_t *map, int id) {
    if (id < map->search_start) map->search_start = id;
    return xarray_remove(&map->elements, id);
}
