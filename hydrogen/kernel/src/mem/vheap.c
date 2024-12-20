#include "mem/vheap.h"
#include "mem/heap.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include <stddef.h>
#include <stdint.h>

// For small allocations, this delegates to normal kalloc/kfree.
//
// Allocations that wouldn't fit in one page are aligned up to a multiple of PAGE_SIZE. Their virtual address is
// allocated by kvmm, and they're mapped using alloc_and_map.

typedef struct {
    size_t size;
} alloc_meta_t;

#define META_OFFSET ((sizeof(alloc_meta_t) + (_Alignof(max_align_t) - 1)) & ~(_Alignof(max_align_t) - 1))
#define ZERO_PTR ((void *)_Alignof(max_align_t))

static void *vmalloc_large(size_t size) {
    size = (size + PAGE_MASK) & ~PAGE_MASK;

    size_t pages = size >> PAGE_SHIFT;

    if (!reserve_pages(pages)) return NULL;

    size_t vaddr;
    if (!vmem_alloc(&kvmm, size, &vaddr)) {
        unreserve_pages(pages);
        return NULL;
    }

    int error = prepare_map(vaddr, size);
    if (error) {
        vmem_free(&kvmm, vaddr, size);
        unreserve_pages(pages);
        return NULL;
    }

    alloc_and_map(vaddr, size);
    return (void *)vaddr;
}

static void vmfree_large(void *ptr, size_t size) {
    size = (size + PAGE_MASK) & ~PAGE_MASK;

    unmap_and_free((uintptr_t)ptr, size);
    vmem_free(&kvmm, (uintptr_t)ptr, size);
    unreserve_pages(size >> PAGE_SHIFT);
}

void *vmalloc(size_t size) {
    if (size == 0) return ZERO_PTR;
    size += META_OFFSET;

    alloc_meta_t *meta;

    if (size <= PAGE_SIZE) {
        meta = kalloc(size);
    } else {
        meta = vmalloc_large(size);
    }

    if (meta != NULL) {
        meta->size = size;
        return (void *)meta + META_OFFSET;
    } else {
        return NULL;
    }
}

void vmfree(void *ptr) {
    if (ptr == NULL || ptr == ZERO_PTR) return;

    alloc_meta_t *meta = ptr - META_OFFSET;

    if (meta->size <= PAGE_SIZE) {
        kfree(meta);
    } else {
        vmfree_large(meta, meta->size);
    }
}
