#include "mem/vheap.h"
#include "mem/heap.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include <stddef.h>
#include <stdint.h>

// For small allocations, this delegates to normal kalloc/kfree.
//
// Allocations that wouldn't fit in one page are aligned up to a multiple of PAGE_SIZE. Their virtual address is picked
// by a bump allocator, but that should be fine since (1) the virtual address space is incredibly large
// and (2) large allocations are extremely rare (mostly occurring during boot), since most subsystems just use kalloc.
// While the virtual address space is never freed, the actual backing memory is, so we shouldn't have to worry about
// that.
// One day we may truly need a proper virtual memory manager, but that isn't the case right now.

typedef struct {
    size_t size;
} alloc_meta_t;

#define META_OFFSET ((sizeof(alloc_meta_t) + (_Alignof(max_align_t) - 1)) & ~(_Alignof(max_align_t) - 1))
#define ZERO_PTR ((void *)_Alignof(max_align_t))

extern const void _end;
static uintptr_t last_alloc_end = (uintptr_t)&_end;
static mutex_t vmalloc_lock;

static void *vmalloc_large(size_t size) {
    size = (size + PAGE_MASK) & ~PAGE_MASK;

    uintptr_t vaddr = last_alloc_end;
    if (!(vaddr & (1ul << 63))) return NULL;

    if (!reserve_pages(size >> PAGE_SHIFT)) return NULL;

    int error = prepare_map(vaddr, size);
    if (error) return NULL;

    alloc_and_map(vaddr, size);
    last_alloc_end = vaddr + size;
    return (void *)vaddr;
}

static void vmfree_large(void *ptr, size_t size) {
    size = (size + PAGE_MASK) & ~PAGE_MASK;
    unmap_and_free((uintptr_t)ptr, size);
    unreserve_pages(size >> PAGE_SHIFT);
}

void *vmalloc(size_t size) {
    if (size == 0) return ZERO_PTR;
    size += META_OFFSET;

    alloc_meta_t *meta;

    if (size <= PAGE_SIZE) {
        meta = kalloc(size);
    } else {
        mutex_lock(&vmalloc_lock);
        meta = vmalloc_large(size);
        mutex_unlock(&vmalloc_lock);
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
        mutex_lock(&vmalloc_lock);
        vmfree_large(meta, meta->size);
        mutex_unlock(&vmalloc_lock);
    }
}
