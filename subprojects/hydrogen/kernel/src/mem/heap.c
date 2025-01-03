#include "mem/heap.h"
#include "compiler.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include "string.h"
#include "util/list.h"
#include <stddef.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))
#define MIN_ALLOC_SIZE 16

_Static_assert(MIN_ALLOC_SIZE >= sizeof(list_node_t), "MIN_ALLOC_SIZE too small");

struct free_obj {
    struct free_obj *next;
};

static page_t *heap_pages[PAGE_SHIFT + 1];
static mutex_t heap_lock[PAGE_SHIFT + 1];

static int size_to_order(size_t size) {
    if (size < MIN_ALLOC_SIZE) size = MIN_ALLOC_SIZE;
    return 64 - __builtin_clzl(size - 1);
}

static void *alloc_order(int order) {
    if (unlikely(order > PAGE_SHIFT)) {
        return NULL;
    } else if (unlikely(order == PAGE_SHIFT)) {
        page_t *page = alloc_page_now();

        if (likely(page)) {
            return page_to_virt(page);
        } else {
            return NULL;
        }
    }

    mutex_lock(&heap_lock[order]);

    page_t *page = heap_pages[order];

    if (likely(page)) {
        struct free_obj *obj = page->heap.objs;
        page->heap.objs = obj->next;

        if (unlikely(--page->heap.free == 0)) {
            heap_pages[order] = page->heap.next;
            if (heap_pages[order]) heap_pages[order]->heap.prev = NULL;
        }

        mutex_unlock(&heap_lock[order]);
        return obj;
    } else {
        mutex_unlock(&heap_lock[order]);

        page = alloc_page_now();

        if (likely(page != NULL)) {
            struct free_obj *objs = page_to_virt(page);
            struct free_obj *last = objs;
            size_t size = 1ul << order;

            for (size_t i = size; i < PAGE_SIZE; i += size) {
                struct free_obj *obj = (void *)objs + i;
                last->next = obj;
                last = obj;
            }

            last->next = NULL;
            page->heap.prev = NULL;
            page->heap.objs = objs->next;
            page->heap.free = (PAGE_SIZE >> order) - 1;

            mutex_lock(&heap_lock[order]);
            page->heap.next = heap_pages[order];
            if (page->heap.next) page->heap.next->heap.prev = page;
            heap_pages[order] = page;
            mutex_unlock(&heap_lock[order]);

            return objs;
        } else {
            return NULL;
        }
    }
}

void *kalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;
    return alloc_order(size_to_order(size));
}

void *krealloc(void *ptr, size_t orig_size, size_t size) {
    if (unlikely(ptr == NULL || ptr == ZERO_PTR)) return kalloc(size);
    if (unlikely(size == 0)) {
        kfree(ptr, orig_size);
        return ZERO_PTR;
    }

    int order = size_to_order(size);
    int orig_order = size_to_order(orig_size);
    if (order == orig_order) return ptr;

    size_t copy_size = orig_order < order ? (1ul << orig_order) : size;

    void *ptr2 = alloc_order(order);
    if (unlikely(!ptr2)) return NULL;
    memcpy(ptr2, ptr, copy_size);
    kfree(ptr, orig_size);
    return ptr2;
}

void kfree(void *ptr, size_t size) {
    if (unlikely(ptr == NULL || ptr == ZERO_PTR)) return;

    page_t *page = virt_to_page(ptr);
    int order = size_to_order(size);

    if (likely(order != PAGE_SHIFT)) {
        mutex_lock(&heap_lock[order]);

        struct free_obj *obj = ptr;
        obj->next = page->heap.objs;
        page->heap.objs = obj;

        if (unlikely(page->heap.free++ == 0)) {
            page->heap.prev = NULL;
            page->heap.next = heap_pages[order];
            if (page->heap.next) page->heap.next->heap.prev = page;
            heap_pages[order] = page;
        } else if (unlikely(page->heap.free == (PAGE_SIZE >> order))) {
            if (page->heap.prev) page->heap.prev->heap.next = page->heap.next;
            else heap_pages[order] = page->heap.next;

            if (page->heap.next) page->heap.next->heap.prev = page->heap.prev;

            free_page_now(page);
        }

        mutex_unlock(&heap_lock[order]);
    } else {
        free_page_now(page);
    }
}
