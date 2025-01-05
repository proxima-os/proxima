#include "mem/vheap.h"
#include "proxima/compiler.h"
#include "mem/heap.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "string.h"
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

    if (unlikely(!reserve_pages(pages))) return NULL;

    size_t vaddr;
    if (unlikely(!vmem_alloc(&kvmm, size, &vaddr))) {
        unreserve_pages(pages);
        return NULL;
    }

    int error = prepare_map(vaddr, size);
    if (unlikely(error)) {
        vmem_free(&kvmm, vaddr, size);
        unreserve_pages(pages);
        return NULL;
    }

    alloc_and_map(vaddr, size);
    return (void *)vaddr;
}

// Tries to resize the allocation in-place. Returns true if successful.
static bool vmrealloc_large(void *ptr, size_t orig_size, size_t size) {
    orig_size = (orig_size + PAGE_MASK) & ~PAGE_MASK;
    size = (size + PAGE_MASK) & ~PAGE_MASK;

    if (orig_size == size) return true;

    size_t extra_pages = orig_size < size ? (size - orig_size) >> PAGE_SHIFT : 0;
    if (extra_pages) {
        if (unlikely(!reserve_pages(extra_pages))) return false;

        int error = prepare_map((uintptr_t)ptr + orig_size, size - orig_size);
        if (unlikely(error)) {
            unreserve_pages(extra_pages);
            return false;
        }
    }

    if (unlikely(!vmem_resize(&kvmm, (uintptr_t)ptr, size))) {
        if (extra_pages) unreserve_pages(extra_pages);
        return false;
    }

    if (extra_pages) {
        alloc_and_map((uintptr_t)ptr + orig_size, size - orig_size);
    } else {
        unmap((uintptr_t)ptr + size, orig_size - size);
    }

    return true;
}

static void vmfree_large(void *ptr, size_t size) {
    size = (size + PAGE_MASK) & ~PAGE_MASK;

    unmap((uintptr_t)ptr, size);
    vmem_free(&kvmm, (uintptr_t)ptr, size);
    unreserve_pages(size >> PAGE_SHIFT);
}

void *vmalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;

    if (likely(size <= PAGE_SIZE)) {
        return kalloc(size);
    } else {
        return vmalloc_large(size);
    }
}

void *vmrealloc(void *ptr, size_t orig_size, size_t size) {
    if (unlikely(ptr == NULL || ptr == ZERO_PTR)) return vmalloc(size);
    if (unlikely(size == 0)) {
        vmfree(ptr, orig_size);
        return ZERO_PTR;
    }

    if (likely(orig_size <= PAGE_SIZE && size <= PAGE_SIZE)) return krealloc(ptr, orig_size, size);
    if (likely(orig_size > PAGE_SIZE && size > PAGE_SIZE && vmrealloc_large(ptr, orig_size, size))) return ptr;

    void *ptr2 = vmalloc(size);
    if (unlikely(!ptr2)) return NULL;
    memcpy(ptr2, ptr, orig_size < size ? orig_size : size);
    vmfree(ptr, orig_size);
    return ptr2;
}

void vmfree(void *ptr, size_t size) {
    if (unlikely(ptr == NULL || ptr == ZERO_PTR)) return;

    if (likely(size <= PAGE_SIZE)) {
        kfree(ptr, size);
    } else {
        vmfree_large(ptr, size);
    }
}
