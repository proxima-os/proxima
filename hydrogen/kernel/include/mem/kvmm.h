#ifndef HYDROGEN_MEM_KVMM_H
#define HYDROGEN_MEM_KVMM_H

#include "mem/pmap.h"
#include "sched/mutex.h"
#include "util/list.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Number of lists for the hash table. Not a fixed cap for the number of allocations, but increasing it improves
// performance.
#define VMEM_ALLOC_HT_CAP 256

typedef struct {
    size_t quantum;
    mutex_t lock;
    list_t ranges;
    list_t free_lists[64];
    list_t alloc_lists[VMEM_ALLOC_HT_CAP];
} vmem_t;

extern vmem_t kvmm;

int vmem_add_range(vmem_t *vmem, size_t start, size_t size);

bool vmem_alloc(vmem_t *vmem, size_t size, size_t *out);

bool vmem_resize(vmem_t *vmem, size_t start, size_t new_size);

void vmem_free(vmem_t *vmem, size_t start, size_t size);

int kvmm_map_mmio(uintptr_t *out, uint64_t phys, size_t size, int flags, cache_mode_t mode);

void kvmm_unmap_mmio(uintptr_t addr, size_t size);

#endif // HYDROGEN_MEM_KVMM_H
