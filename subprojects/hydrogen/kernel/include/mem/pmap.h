#ifndef HYDROGEN_MEM_PMAP_H
#define HYDROGEN_MEM_PMAP_H

#include <stddef.h>
#include <stdint.h>

#define PMAP_WRITE 1
#define PMAP_EXEC 2

#define MAX_USER_VIRT_ADDR 0x7ffffffff000
#define MIN_KERNEL_VIRT_ADDR 0xffff800000000000

#define PTE_PRESENT 1
#define PTE_WRITABLE 2
#define PTE_USERSPACE 4
#define PTE_ACCESSED 0x20
#define PTE_DIRTY 0x40
#define PTE_HUGE 0x80
#define PTE_GLOBAL 0x100
#define PTE_ANON 0x200
#define PTE_COW 0x400
#define PTE_ADDR 0xffffffffff000
#define PTE_NX 0x8000000000000000

#define PTE_CACHE_WT (1u << 3)
#define PTE_CACHE_UC (3u << 3)
#define PTE_CACHE_WP (1u << 6)
#define PTE_CACHE_WC ((1u << 6) | (1u << 3))

typedef enum {
    CACHE_WRITEBACK,
    CACHE_WRITETHROUGH,
    CACHE_NONE_WEAK,
    CACHE_NONE,
    CACHE_WRITE_PROTECT,
    CACHE_WRITE_COMBINE,
} cache_mode_t;

typedef struct pmap pmap_t;

void init_pmap(void);

int pmap_create(pmap_t **out);

// current pmap must be locked
int pmap_clone(pmap_t **out);

// must be called with irqs disabled
void pmap_switch(pmap_t *target);

void pmap_destroy(pmap_t *pmap);

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

// Extends the HHDM to cover a new range
void extend_hhdm(uint64_t paddr, size_t size);

#endif // HYDROGEN_MEM_PMAP_H
