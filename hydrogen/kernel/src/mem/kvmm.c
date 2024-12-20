#include "mem/kvmm.h"
#include "errno.h"
#include "mem/heap.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include "string.h"
#include "util/list.h"
#include "util/panic.h"
#include <stdint.h>

struct range_info {
    uint64_t hash;
    list_node_t node;
    list_node_t snode; // when free node for free_list, otherwise node for hash table
    size_t start;
    size_t size;
    int order;
    bool free;
};

vmem_t kvmm = {.quantum = PAGE_SIZE};

// returns `n` in `2^n` for the highest power of two <= `size`
// `size` must not be 0
static int get_order(size_t size) {
    return 63 - __builtin_clzl(size);
}

// returns `n` in `2^n` for the lowest power of two >= `size`
// `size` must not be 0
static int get_alloc_order(size_t size) {
    return size > 1 ? 64 - __builtin_clzl(size - 1) : 0;
}

static void update_order(vmem_t *vmem, struct range_info *info) {
    int new_order = get_order(info->size);

    if (info->free && new_order != info->order) {
        list_remove(&vmem->free_lists[info->order], &info->snode);
        list_insert_head(&vmem->free_lists[new_order], &info->snode);
    }

    info->order = new_order;
}

static uint64_t hash(uint64_t x) {
    x *= 0x655957f30ca7c0eb;
    x = __builtin_bswap64(x);
    x ^= x >> 11;
    x *= 0xe16620abcb836b8f;
    x ^= x >> 8;
    x *= 0xd0b3c470eea38fe3;
    return x;
}

static bool try_coalesce(vmem_t *vmem, struct range_info *next, size_t start, size_t size) {
    struct range_info *prev = node_to_obj(struct range_info, node, next ? next->node.prev : vmem->ranges.last);
    if (!prev && !next) return false;

    ASSERT(prev == NULL || prev->start + prev->size <= start);
    ASSERT(next == NULL || start + size <= next->start);

    bool prev_merge = prev != NULL && prev->free && prev->start + prev->size == start;
    bool next_merge = next != NULL && next->free && start + size == next->start;

    if (prev_merge) {
        prev->size += size;

        if (next_merge) {
            prev->size += next->size;

            list_remove(&vmem->ranges, &next->node);
            list_remove(&vmem->free_lists[next->order], &next->snode);
            kfree(next);
        }

        update_order(vmem, prev);
        return true;
    } else if (next_merge) {
        next->start -= size;
        next->size += size;
        update_order(vmem, next);
        return true;
    } else {
        return false;
    }
}

int vmem_add_range(vmem_t *vmem, size_t start, size_t size) {
    if (size == 0) return 0;

    ASSERT(start % vmem->quantum == 0);
    ASSERT(size % vmem->quantum == 0);
    ASSERT(start + (size - 1) > start);

    mutex_lock(&vmem->lock);

    struct range_info *next = NULL;

    list_foreach(vmem->ranges, struct range_info, snode, cur) {
        if (cur->start >= start) {
            next = cur;
            break;
        }
    }

    if (!try_coalesce(vmem, next, start, size)) {
        struct range_info *info = kalloc(sizeof(*info));
        if (!info) {
            mutex_unlock(&vmem->lock);
            return ENOMEM;
        }
        memset(info, 0, sizeof(*info));
        info->start = start;
        info->size = size;
        info->order = get_order(size);
        info->free = true;

        list_insert_before(&vmem->ranges, next ? &next->node : NULL, &info->node);
        list_insert_head(&vmem->free_lists[info->order], &info->snode);
    }

    mutex_unlock(&vmem->lock);
    return 0;
}

bool vmem_alloc(vmem_t *vmem, size_t size, size_t *out) {
    if (size == 0) {
        *out = 0;
        return true;
    }

    ASSERT(size % vmem->quantum == 0);

    mutex_lock(&vmem->lock);

    struct range_info *info;

    for (int i = get_alloc_order(size); i < 64; i++) {
        info = node_to_obj(struct range_info, snode, list_remove_head(&vmem->free_lists[i]));
        if (info != NULL) break;
    }

    if (info == NULL) {
        mutex_unlock(&vmem->lock);
        return false;
    }

    ASSERT(info->free);

    if (info->size != size) {
        struct range_info *info2 = kalloc(sizeof(*info2));
        if (!info2) {
            mutex_unlock(&vmem->lock);
            return false;
        }

        size_t start = info->start;

        info->start += size;
        info->size -= size;
        info->order = get_order(info->size);
        list_insert_head(&vmem->free_lists[info->order], &info->snode);

        memset(info2, 0, sizeof(*info2));
        info2->hash = hash(start);
        info2->start = start;
        info2->size = size;
        info2->order = get_order(size);

        list_insert_before(&vmem->ranges, &info->node, &info2->node);
        info = info2;
    } else {
        info->hash = hash(info->start);
        info->free = false;
    }

    list_insert_head(&vmem->alloc_lists[info->hash % VMEM_ALLOC_HT_CAP], &info->snode);
    mutex_unlock(&vmem->lock);

    *out = info->start;
    return true;
}

void vmem_free(vmem_t *vmem, size_t start, size_t size) {
    if (size == 0) return;

    ASSERT(start % vmem->quantum == 0);
    ASSERT(size % vmem->quantum == 0);

    size_t index = hash(start) % VMEM_ALLOC_HT_CAP;

    mutex_lock(&vmem->lock);

    struct range_info *info = NULL;

    list_foreach(vmem->alloc_lists[index], struct range_info, snode, cur) {
        if (cur->start == start) {
            info = cur;
            break;
        }
    }

    ASSERT(info != NULL);
    ASSERT(!info->free);
    ASSERT(info->size == size);

    struct range_info *next = node_to_obj(struct range_info, node, info->node.next);

    list_remove(&vmem->ranges, &info->node);
    list_remove(&vmem->alloc_lists[index], &info->snode);

    if (!try_coalesce(vmem, next, info->start, info->size)) {
        info->free = true;
        list_insert_before(&vmem->ranges, next ? &next->node : NULL, &info->node);
        list_insert_head(&vmem->free_lists[info->order], &info->snode);
    } else {
        kfree(info);
    }

    mutex_unlock(&vmem->lock);
}

int kvmm_map_mmio(uintptr_t *out, uint64_t phys, size_t size, int flags, cache_mode_t mode) {
    uint64_t offset = phys & PAGE_MASK;
    uint64_t end = (phys + size + PAGE_MASK) & ~PAGE_MASK;
    phys -= offset;
    size = end - phys;

    if (!vmem_alloc(&kvmm, size, out)) return ENOMEM;

    int error = prepare_map(*out, size);
    if (error) {
        vmem_free(&kvmm, *out, size);
        return error;
    }

    do_map(*out, phys, size, flags, mode);

    *out += offset;
    return 0;
}

void kvmm_unmap_mmio(uintptr_t addr, size_t size) {
    uintptr_t offset = addr & PAGE_MASK;
    uintptr_t end = (addr + size + PAGE_MASK) & ~PAGE_MASK;
    addr -= offset;
    size = end - addr;

    unmap(addr, size);
    vmem_free(&kvmm, addr, size);
}
