#ifndef HYDROGEN_MEM_PMAP_H
#define HYDROGEN_MEM_PMAP_H

#include <stddef.h>
#include <stdint.h>

#define PMAP_WRITE 1
#define PMAP_EXEC 2

#define MIN_KERNEL_VIRT_ADDR 0xffff800000000000

typedef enum {
    CACHE_WRITEBACK,
    CACHE_WRITETHROUGH,
    CACHE_NONE_WEAK,
    CACHE_NONE,
    CACHE_WRITE_PROTECT,
    CACHE_WRITE_COMBINE,
} cache_mode_t;

void init_pmap(void);

void switch_to_kernel_mappings(void);

int prepare_map(uintptr_t vaddr, size_t size);

// You MUST call prepare_map on the range first
void do_map(uintptr_t vaddr, uint64_t paddr, size_t size, int flags, cache_mode_t mode);

// You MUST call prepare_map on the range first, and reserve_pages on the size.
void alloc_and_map(uintptr_t vaddr, size_t size);

// You MUST call prepare_map on the range first
void remap(uintptr_t vaddr, size_t size, int flags);

// You MUST call prepare_map on the range first
void unmap(uintptr_t vaddr, size_t size);

// You MUST call prepare_map on the range first. Does not call unreserve_pages.
// Note that the affected area MUST have been mapped by alloc_and_map.
void unmap_and_free(uintptr_t vaddr, size_t size);

// Extends the HHDM to cover a new range
void extend_hhdm(uint64_t paddr, size_t size);

#endif // HYDROGEN_MEM_PMAP_H
