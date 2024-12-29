#include "mem/kvmm.h"
#include "hydrogen/error.h"
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
    x *= 0xe9770214b82cf957;
    x ^= x >> 47;
    x *= 0x2bdd9d20d060fc9b;
    x ^= x >> 44;
    x *= 0x65c487023b406173;
    return x;
}

static bool try_coalesce(vmem_t *vmem, struct range_info *next, size_t start, size_t size) {
    struct range_info *prev = node_to_obj(struct range_info, node, next ? next->node.prev : vmem->ranges.last);
    if (!prev && !next) return false;

    bool prev_merge = prev != NULL && prev->free && prev->start + prev->size == start;
    bool next_merge = next != NULL && next->free && start + size == next->start;

    if (prev_merge) {
        prev->size += size;

        if (next_merge) {
            prev->size += next->size;

            list_remove(&vmem->ranges, &next->node);
            list_remove(&vmem->free_lists[next->order], &next->snode);
            kfree(next, sizeof(*next));
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

static bool add_free_range(vmem_t *vmem, struct range_info *next, size_t start, size_t size) {
    if (!try_coalesce(vmem, next, start, size)) {
        struct range_info *info = kalloc(sizeof(*info));
        if (!info) return false;
        memset(info, 0, sizeof(*info));
        info->start = start;
        info->size = size;
        info->order = get_order(size);
        info->free = true;

        list_insert_before(&vmem->ranges, next ? &next->node : NULL, &info->node);
        list_insert_head(&vmem->free_lists[info->order], &info->snode);
    }

    return true;
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

    bool success = add_free_range(vmem, next, start, size);

    mutex_unlock(&vmem->lock);
    return success ? 0 : ERR_OUT_OF_MEMORY;
}

static struct range_info *get_range_for_alloc(vmem_t *vmem, size_t size) {
    int min_order = get_alloc_order(size);

    for (int i = min_order; i < 64; i++) {
        struct range_info *info = node_to_obj(struct range_info, snode, list_remove_head(&vmem->free_lists[i]));
        if (info != NULL) return info;
    }

    if (min_order > 1 && size != (1ul << min_order)) {
        // The previous free list might have a range that is big enough to allocate from, since a free list contains
        // 2^i <= size < 2^(i + 1) and min_order is the i in 2^(i - 1) < size <= 2^i

        list_foreach(vmem->free_lists[min_order - 1], struct range_info, snode, cur) {
            if (cur->size >= size) {
                list_remove(&vmem->free_lists[min_order - 1], &cur->snode);
                return cur;
            }
        }
    }

    return NULL;
}

bool vmem_alloc(vmem_t *vmem, size_t size, size_t *out) {
    if (size == 0) {
        *out = 0;
        return true;
    }

    ASSERT(size % vmem->quantum == 0);

    mutex_lock(&vmem->lock);

    struct range_info *info = get_range_for_alloc(vmem, size);

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

static bool can_expand_into(struct range_info *next, size_t expand_start, size_t expand_size) {
    return next != NULL && next->free && next->start == expand_start && next->size >= expand_size;
}

bool vmem_resize(vmem_t *vmem, size_t start, size_t new_size) {
    if (new_size == 0) {
        vmem_free(vmem, start, new_size);
        return false;
    }

    ASSERT(start % vmem->quantum == 0);
    ASSERT(new_size % vmem->quantum == 0);

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

    struct range_info *next = node_to_obj(struct range_info, node, info->node.next);

    if (new_size < info->size) {
        if (!add_free_range(vmem, next, start + new_size, info->size - new_size)) {
            mutex_unlock(&vmem->lock);
            return false;
        }

        info->size = new_size;
    } else if (new_size > info->size) {
        size_t delta = new_size - info->size;

        if (!can_expand_into(next, info->start + info->size, delta)) {
            mutex_unlock(&vmem->lock);
            return false;
        }

        info->size = new_size;
        next->start += delta;
        next->size -= delta;

        int new_order = get_order(next->size);
        if (new_order != next->order) {
            list_remove(&vmem->free_lists[next->order], &next->snode);
            list_insert_head(&vmem->free_lists[new_order], &next->snode);
            next->order = new_order;
        }
    }

    mutex_unlock(&vmem->lock);
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
        kfree(info, sizeof(*info));
    }

    mutex_unlock(&vmem->lock);
}

int kvmm_map_mmio(uintptr_t *out, uint64_t phys, size_t size, int flags, cache_mode_t mode) {
    uint64_t offset = phys & PAGE_MASK;
    uint64_t end = (phys + size + PAGE_MASK) & ~PAGE_MASK;
    phys -= offset;
    size = end - phys;

    if (!vmem_alloc(&kvmm, size, out)) return ERR_OUT_OF_MEMORY;

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
