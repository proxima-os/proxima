#include "mem/heap.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include "util/list.h"
#include <stddef.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))
#define MIN_ALLOC_SIZE 16

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
        return page ? page_to_virt(page) : NULL;
    }

    mutex_lock(&heap_lock[order]);
    void *ptr = list_remove_head(&free_objects[order]);
    mutex_unlock(&heap_lock[order]);

    if (ptr == NULL) {
        page_t *page = alloc_page_now();

        if (page != NULL) {
            page->heap.order = order;
            ptr = page_to_virt(page);

            if (order != PAGE_SHIFT) {
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
    }

    return ptr;
}

void kfree(void *ptr) {
    if (ptr == NULL) return;
    if (ptr == ZERO_PTR) return;

    int order = virt_to_page(ptr)->heap.order;

    if (order != PAGE_SHIFT) {
        mutex_lock(&heap_lock[order]);
        list_insert_head(&free_objects[order], ptr);
        mutex_unlock(&heap_lock[order]);
    } else {
        free_page_now(virt_to_page(ptr));
    }
}
