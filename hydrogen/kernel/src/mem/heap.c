#include "mem/heap.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include "util/list.h"
#include <stddef.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))
#define MIN_ALLOC_SIZE 16

_Static_assert(MIN_ALLOC_SIZE >= sizeof(list_node_t), "MIN_ALLOC_SIZE too small");

static list_t free_objects[PAGE_SHIFT + 1];
static mutex_t heap_lock[PAGE_SHIFT + 1];

static int size_to_order(size_t size) {
    return 64 - __builtin_clzl(size - 1);
}

void *kalloc(size_t size) {
    if (size == 0) return ZERO_PTR;
    if (size < MIN_ALLOC_SIZE) size = MIN_ALLOC_SIZE;

    int order = size_to_order(size);

    if (order > PAGE_SHIFT) {
        return NULL;
    } else if (order == PAGE_SHIFT) {
        page_t *page = alloc_page_now();

        if (page) {
            page->heap.order = PAGE_SHIFT;
            return page_to_virt(page);
        } else {
            return NULL;
        }
    }

    mutex_lock(&heap_lock[order]);

    void *ptr = list_remove_head(&free_objects[order]);
    if (ptr) virt_to_page(ptr)->heap.allocated += 1;

    mutex_unlock(&heap_lock[order]);

    if (ptr == NULL) {
        page_t *page = alloc_page_now();

        if (page != NULL) {
            page->heap.allocated = 1;
            page->heap.order = order;
            ptr = page_to_virt(page);

            size = 1ul << order;

            list_t elements = {};

            for (size_t offset = size; offset < PAGE_SIZE; offset += size) {
                list_insert_tail(&elements, ptr + offset);
            }

            mutex_lock(&heap_lock[order]);
            list_transfer_tail(&free_objects[order], &elements);
            mutex_unlock(&heap_lock[order]);
        }
    }

    return ptr;
}

void kfree(void *ptr) {
    if (ptr == NULL) return;
    if (ptr == ZERO_PTR) return;

    page_t *page = virt_to_page(ptr);
    int order = page->heap.order;

    if (order != PAGE_SHIFT) {
        mutex_lock(&heap_lock[order]);

        list_insert_head(&free_objects[order], ptr);

        if (--page->heap.allocated == 0) {
            ptr = page_to_virt(page);
            size_t size = 1ul << order;

            for (size_t i = 0; i < PAGE_SIZE; i += size) {
                list_remove(&free_objects[order], ptr + i);
            }

            free_page_now(page);
        }

        mutex_unlock(&heap_lock[order]);
    } else {
        free_page_now(virt_to_page(ptr));
    }
}
