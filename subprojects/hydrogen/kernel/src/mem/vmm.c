#include "mem/vmm.h"
#include "hydrogen/error.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "proxima/compiler.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "string.h"
#include "sys/vdso.h"
#include "util/list.h"
#include "util/panic.h"
#include <stdint.h>

#define VMM_FLAGS (VMM_PRIVATE | VMM_EXACT | VMM_EXEC | VMM_WRITE | VMM_READ)
#define VMM_PFLAG (VMM_EXEC | VMM_WRITE | VMM_READ)

int vmm_create(vmm_t **out) {
    vmm_t *vmm = vmalloc(sizeof(*vmm));
    if (!vmm) return ERR_OUT_OF_MEMORY;
    memset(vmm, 0, sizeof(*vmm));
    vmm->references = 1;

    int error = pmap_create(&vmm->pmap);
    if (error) {
        vmfree(vmm, sizeof(*vmm));
        return error;
    }

    *out = vmm;
    return 0;
}

static bool requires_reservation(int flags, vm_object_t *object) {
    return (flags & VMM_PFLAG) != 0 && (object == NULL || (flags & VMM_PRIVATE) != 0);
}

static void free_regions(vmm_t *vmm) {
    vm_region_t *cur = node_to_obj(vm_region_t, node, vmm->reg_list.first);

    while (cur != NULL) {
        vm_region_t *next = node_to_obj(vm_region_t, node, cur->node.next);
        if (requires_reservation(cur->flags, cur->object)) {
            unreserve_pages((cur->tail - cur->head + 1) >> PAGE_SHIFT);
        }
        if (cur->object) vmo_deref(cur->object);
        vmfree(cur, sizeof(*cur));
        cur = next;
    }
}

static void tree_add(vmm_t *vmm, vm_region_t *region) {
    vm_region_t *parent = NULL;
    vm_region_t **field = &vmm->regions;
    vm_region_t *cur = *field;

    while (cur != NULL) {
        ASSERT(cur->head != region->head);

        parent = cur;

        if (region->head < cur->head) field = &cur->left;
        else field = &cur->right;

        cur = *field;
    }

    region->parent = parent;
    region->left = NULL;
    region->right = NULL;
    *field = region;
}

static int clone_regions(vmm_t *src, vmm_t *dest) {
    list_foreach(src->reg_list, vm_region_t, node, cur) {
        size_t pages = (cur->tail - cur->head + 1) >> PAGE_SHIFT;
        bool reserve = requires_reservation(cur->flags, cur->object);

        if (reserve && unlikely(!reserve_pages(pages))) {
            free_regions(dest);
            return ERR_OUT_OF_MEMORY;
        }

        vm_region_t *reg = vmalloc(sizeof(*reg));
        if (unlikely(!reg)) {
            if (reserve) unreserve_pages(pages);
            free_regions(dest);
            return ERR_OUT_OF_MEMORY;
        }
        memset(reg, 0, sizeof(*reg));
        reg->head = cur->head;
        reg->tail = cur->tail;
        reg->flags = cur->flags;
        reg->object = cur->object;
        reg->offset = cur->offset;

        if (reg->object) vmo_ref(reg->object);

        list_insert_tail(&dest->reg_list, &reg->node);
        tree_add(dest, reg);
    }

    return 0;
}

int vmm_clone(vmm_t **out) {
    vmm_t *vmm = vmalloc(sizeof(*vmm));
    if (unlikely(!vmm)) return ERR_OUT_OF_MEMORY;
    memset(vmm, 0, sizeof(*vmm));
    vmm->references = 1;

    mutex_lock(&vmm->lock);

    int error = clone_regions(current_proc->vmm, vmm);
    if (unlikely(error)) {
        vmfree(vmm, sizeof(*vmm));
        mutex_unlock(&vmm->lock);
        return error;
    }

    error = pmap_clone(&vmm->pmap);
    if (unlikely(error)) {
        free_regions(vmm);
        vmfree(vmm, sizeof(*vmm));
        mutex_unlock(&vmm->lock);
        return error;
    }

    mutex_unlock(&vmm->lock);

    *out = vmm;
    return 0;
}

void vmm_ref(vmm_t *vmm) {
    __atomic_fetch_add(&vmm->references, 1, __ATOMIC_ACQ_REL);
}

void vmm_deref(vmm_t *vmm) {
    if (__atomic_fetch_sub(&vmm->references, 1, __ATOMIC_ACQ_REL) == 1) {
        pmap_destroy(vmm->pmap);
        free_regions(vmm);
        vmfree(vmm, sizeof(*vmm));
    }
}

void vmm_switch(vmm_t *target) {
    pmap_switch(target ? target->pmap : NULL);
}

static int get_pmap_flags(int flags) {
    int pflag = 0;
    if (flags & VMM_WRITE) pflag |= PMAP_WRITE;
    if (flags & VMM_EXEC) pflag |= PMAP_EXEC;
    return pflag;
}

// Find the highest region where tail < addr
static vm_region_t *find_highest_below(vmm_t *vmm, uintptr_t addr) {
    vm_region_t *prev = NULL;

    list_foreach(vmm->reg_list, vm_region_t, node, cur) {
        if (cur->tail >= addr) break;
        prev = cur;
    }

    return prev;
}

static void tree_rem(vmm_t *vmm, vm_region_t *region) {
    vm_region_t *parent = region->parent;
    vm_region_t *successor;

    if (region->left == NULL && region->right == NULL) {
        successor = NULL;
    } else if (region->right == NULL) {
        successor = region->left;
    } else if (region->left == NULL) {
        successor = region->right;
    } else {
        successor = region->right;
        while (successor->left != NULL) successor = successor->left;

        successor->left = region->left;

        if (successor->parent != region) {
            successor->parent->left = successor->right;
            successor->right = region->right;
        }
    }

    if (successor) successor->parent = parent;

    if (parent) {
        if (parent->left == region) parent->left = successor;
        else parent->right = successor;
    } else {
        vmm->regions = successor;
    }
}

static void on_remove_part(uintptr_t head, uintptr_t tail, int flags, bool reserve) {
    size_t size = tail - head + 1;
    if (flags & VMM_PFLAG) unmap(head, size);
    if (reserve) unreserve_pages(size >> PAGE_SHIFT);
}

static void remove_region(vmm_t *vmm, vm_region_t *region) {
    list_remove(&vmm->reg_list, &region->node);
    tree_rem(vmm, region);
}

static void insert_before(vmm_t *vmm, vm_region_t *next, vm_region_t *region) {
    list_insert_before(&vmm->reg_list, next ? &next->node : NULL, &region->node);
    tree_add(vmm, region);
}

static bool can_merge(vm_region_t *r1, vm_region_t *r2) {
    if (r1->flags != r2->flags) return false;
    if (r1->object != r2->object) return false;
    if (!r1->object) return true;

    // relies on two's complement arithmetic
    size_t addr_diff = r2->head - r1->head;
    size_t offs_diff = r2->offset - r1->offset;
    return addr_diff == offs_diff;
}

static void merge_or_insert(vmm_t *vmm, vm_region_t *prev, vm_region_t *next, vm_region_t *region) {
    bool merge_prev = prev != NULL && prev->tail + 1 == region->head && can_merge(prev, region);
    bool merge_next = next != NULL && region->tail + 1 == next->head && can_merge(region, next);

    if (merge_prev && merge_next) {
        prev->tail = next->tail;
        remove_region(vmm, next);
        if (next->object) vmo_deref(next->object);
        vmfree(next, sizeof(*next));
    } else if (merge_prev) {
        prev->tail = region->tail;
    } else if (merge_next) {
        tree_rem(vmm, next);
        next->head = region->head;
        tree_add(vmm, next);
    } else {
        insert_before(vmm, next, region);
        if (region->object) vmo_ref(region->object);
        return;
    }

    vmfree(region, sizeof(*region));
}

static int remove_overlapping(vmm_t *vmm, vm_region_t **prev, vm_region_t **next, uintptr_t head, uintptr_t tail) {
    vm_region_t *start = *next;
    vm_region_t *end = start;

    while (end != NULL && end->head <= tail) {
        // prevent userspace from removing vdso regions
        // this has to be done in a separate pass because otherwise partial unmaps may occur
        if (end->object == &vdso_object) return ERR_INVALID_ARGUMENT;

        end = node_to_obj(vm_region_t, node, end->node.next);
    }

    vm_region_t *cur = start;

    while (cur != NULL && cur->head <= tail) {
        vm_region_t *next = node_to_obj(vm_region_t, node, cur->node.next);

        bool reserve = requires_reservation(cur->flags, cur->object);

        if (cur->head >= head && cur->tail <= tail) {
            // the entire region must be removed
            remove_region(vmm, cur);
            on_remove_part(cur->head, cur->tail, cur->flags, reserve);
            if (cur->object) vmo_deref(cur->object);
            vmfree(cur, sizeof(*cur));
        } else if (cur->tail <= tail) {
            // cur->head < head, so adjust tail
            on_remove_part(head, cur->tail, cur->flags, reserve);
            cur->tail = head - 1;
            *prev = cur;
        } else if (cur->head >= head) {
            // cur->tail > tail, so adjust head
            on_remove_part(cur->head, tail, cur->flags, reserve);
            tree_rem(vmm, cur);
            cur->offset += tail - cur->head + 1;
            cur->head = tail + 1;
            tree_add(vmm, cur);
            next = cur;
        } else {
            // cur->head < head && cur->tail > tail, so split in two
            // this should only be possible if this is the only region to change. verify that, because otherwise
            // an allocation failure here could cause a partial unmap
            ASSERT(cur == start && (next == NULL || next->head > tail));

            vm_region_t *tpart = vmalloc(sizeof(*tpart));
            if (unlikely(!tpart)) return ERR_OUT_OF_MEMORY;
            memset(tpart, 0, sizeof(*tpart));
            tpart->flags = cur->flags;
            tpart->head = tail + 1;
            tpart->tail = cur->tail;
            tpart->object = cur->object;
            tpart->offset = cur->offset;

            if (tpart->object) vmo_ref(tpart->object);

            cur->tail = head - 1;

            insert_before(vmm, next, tpart);
            on_remove_part(head, tail, cur->flags, reserve);

            *prev = cur;
            next = tpart;
        }

        cur = next;
    }

    *next = cur;
    return 0;
}

static int add_exact(vmm_t *vmm, uintptr_t addr, size_t size, int flags, vm_object_t *object, size_t offset) {
    uintptr_t tail = addr + (size - 1);
    if (unlikely(tail < addr)) return ERR_OUT_OF_MEMORY;
    if (unlikely(object && (offset & PAGE_MASK) != (addr & PAGE_MASK))) return ERR_INVALID_ARGUMENT;

    addr &= ~PAGE_MASK;
    tail |= PAGE_MASK;

    if (unlikely(addr < PAGE_SIZE)) return ERR_OUT_OF_MEMORY;
    if (unlikely(tail >= MAX_USER_VIRT_ADDR)) return ERR_OUT_OF_MEMORY;

    mutex_lock(&vmm->lock);

    vm_region_t *prev = find_highest_below(vmm, addr);
    vm_region_t *next = node_to_obj(vm_region_t, node, prev ? prev->node.next : vmm->reg_list.first);

    size = tail - addr + 1;

    bool reserve = requires_reservation(flags, object);
    int error = !reserve || reserve_pages(size >> PAGE_SHIFT) ? 0 : ERR_OUT_OF_MEMORY;

    if (likely(error == 0)) {
        if (flags & VMM_PFLAG) {
            error = prepare_map(addr, size);
        }

        if (likely(error == 0)) {
            vm_region_t *region = vmalloc(sizeof(*region));

            if (likely(region)) {
                error = remove_overlapping(vmm, &prev, &next, addr, tail);

                if (likely(error == 0)) {
                    memset(region, 0, sizeof(*region));
                    region->head = addr;
                    region->tail = tail;
                    region->flags = flags;
                    region->object = object;
                    region->offset = offset & ~PAGE_MASK;

                    merge_or_insert(vmm, prev, next, region);
                } else {
                    vmfree(region, sizeof(*region));
                }
            }
        }

        if (unlikely(error) && reserve) {
            unreserve_pages(size >> PAGE_SHIFT);
        }
    }

    mutex_unlock(&vmm->lock);
    return error;
}

struct found_pos {
    uintptr_t head;
    uintptr_t tail;
    vm_region_t *prev;
    vm_region_t *next;
};

static int find_position(vmm_t *vmm, uintptr_t addr, size_t size, struct found_pos *out) {
    size_t limit = size - 1;

    if (addr != 0) {
        uintptr_t tail = addr + size;
        if (unlikely(tail < addr)) goto choose;

        addr &= ~PAGE_MASK;
        tail |= PAGE_MASK;

        if (unlikely(tail >= MAX_USER_VIRT_ADDR)) goto choose;

        vm_region_t *prev = find_highest_below(vmm, addr);
        vm_region_t *next = node_to_obj(vm_region_t, node, prev ? prev->node.next : vmm->reg_list.first);

        ASSERT(prev == NULL || prev->tail < addr);

        if (next == NULL || tail < next->head) {
            out->head = addr;
            out->tail = tail;
            out->prev = prev;
            out->next = next;
            return 0;
        }
    }
choose:
    limit |= PAGE_MASK;

    vm_region_t *prev = node_to_obj(vm_region_t, node, vmm->reg_list.last);
    vm_region_t *next = NULL;

    for (;;) {
        uintptr_t prev_tail = prev ? prev->tail : PAGE_MASK;
        uintptr_t next_head = next ? next->head : (MAX_USER_VIRT_ADDR & ~PAGE_MASK);

        uintptr_t alloc_tail = next_head - 1;
        uintptr_t alloc_head = alloc_tail - limit;
        if (unlikely(alloc_head > alloc_tail)) break;

        if (prev_tail < alloc_head) {
            out->prev = prev;
            out->next = next;
            out->head = alloc_head;
            out->tail = alloc_tail;
            return 0;
        }

        if (!prev) break;

        next = prev;
        prev = node_to_obj(vm_region_t, node, prev->node.prev);
    }

    return ERR_OUT_OF_MEMORY;
}

int vmm_add(uintptr_t *addr, size_t size, int flags, vm_object_t *object, size_t offset) {
    if (unlikely(flags & ~VMM_FLAGS)) return ERR_INVALID_ARGUMENT;
    if (unlikely(size == 0)) return ERR_INVALID_ARGUMENT;
    if (!(flags & VMM_WRITE)) flags &= ~VMM_PRIVATE;

    if (object) {
        if (unlikely(!object->ops->allow_flags(object, flags))) return ERR_ACCESS_DENIED;

        size_t end = size + offset;
        if (end < size || end > object->size) return ERR_OVERFLOW;
    }

    vmm_t *vmm = current_proc->vmm;

    if (flags & VMM_EXACT) return add_exact(vmm, *addr, size, flags & ~VMM_EXACT, object, offset);

    mutex_lock(&vmm->lock);

    struct found_pos pos;
    int error = find_position(vmm, *addr, size, &pos);
    if (unlikely(error)) goto out;

    size = pos.tail - pos.head + 1;

    bool reserve = requires_reservation(flags, object);
    if (reserve && unlikely(!reserve_pages(size >> PAGE_SHIFT))) {
        error = ERR_OUT_OF_MEMORY;
        goto out;
    }

    if (flags & VMM_PFLAG) {
        error = prepare_map(pos.head, size);
        if (unlikely(error)) {
            if (reserve) unreserve_pages(size >> PAGE_SHIFT);
            goto out;
        }
    }

    vm_region_t *region = vmalloc(sizeof(*region));

    if (likely(region)) {
        memset(region, 0, sizeof(*region));
        region->head = pos.head;
        region->tail = pos.tail;
        region->flags = flags & ~VMM_EXACT;
        region->object = object;
        region->offset = offset & ~PAGE_MASK;
        merge_or_insert(vmm, pos.prev, pos.next, region);
    } else {
        error = ERR_OUT_OF_MEMORY;
    }

    if (likely(error == 0)) {
        if (object) pos.head |= offset & PAGE_MASK;
        *addr = pos.head;
    } else if (reserve) {
        unreserve_pages(size >> PAGE_SHIFT);
    }

out:
    mutex_unlock(&vmm->lock);
    return error;
}

static vm_region_t *next_region(vm_region_t *prev) {
    return node_to_obj(vm_region_t, node, prev->node.next);
}

int vmm_alter(uintptr_t addr, size_t size, int flags) {
    if (unlikely(flags & ~VMM_PFLAG)) return ERR_INVALID_ARGUMENT;
    if (unlikely(size == 0)) return 0;

    vmm_t *vmm = current_proc->vmm;

    uintptr_t tail = addr + (size - 1);
    addr &= ~PAGE_MASK;
    tail |= PAGE_MASK;

    if (tail >= MAX_USER_VIRT_ADDR) return ERR_INVALID_ARGUMENT;

    mutex_lock(&vmm->lock);

    vm_region_t *prev = find_highest_below(vmm, addr);
    vm_region_t *first = node_to_obj(vm_region_t, node, prev ? prev->node.next : vmm->reg_list.first);
    vm_region_t *last = NULL;
    vm_region_t *next = first;
    int error = 0;

    // find boundaries
    size_t tot_extra_pages = 0;

    while (next != NULL && next->head <= tail) {
        if (next->object && !next->object->ops->allow_flags(next->object, flags)) {
            mutex_unlock(&vmm->lock);
            return ERR_ACCESS_DENIED;
        }

        int new_flags = (next->flags & ~VMM_PFLAG) | flags;
        size_t size = next->tail - next->head + 1;

        if ((next->flags & VMM_PFLAG) == 0 && (new_flags & VMM_PFLAG) != 0) {
            bool reserve = requires_reservation(new_flags, next->object);
            if (reserve && unlikely(!reserve_pages(size >> PAGE_SHIFT))) {
                unreserve_pages(tot_extra_pages);
                mutex_unlock(&vmm->lock);
                return ERR_OUT_OF_MEMORY;
            }

            tot_extra_pages += size >> PAGE_SHIFT;

            error = prepare_map(next->head, size);
            if (unlikely(error)) {
                unreserve_pages(tot_extra_pages);
                mutex_unlock(&vmm->lock);
                return ERR_OUT_OF_MEMORY;
            }
        }

        last = next;
        next = next_region(next);
    }

    if (first != next) {
        ASSERT(first != NULL);
        ASSERT(last != NULL);

        // split any regions that need to be split
        bool first_needs_split = first->head < addr;
        bool last_needs_split = last->tail > tail;

        if (first_needs_split && last_needs_split && first == last) {
            vm_region_t *new_regions = vmalloc(sizeof(*new_regions) * 2);
            if (unlikely(!new_regions)) {
                unreserve_pages(tot_extra_pages);
                mutex_unlock(&vmm->lock);
                return ERR_OUT_OF_MEMORY;
            }

            new_regions[0].head = addr;
            new_regions[0].tail = tail;
            new_regions[0].flags = first->flags;
            new_regions[0].object = first->object;
            new_regions[0].offset = first->offset;
            insert_before(vmm, next_region(first), &new_regions[0]);

            new_regions[1].head = tail + 1;
            new_regions[1].tail = first->tail;
            new_regions[1].flags = first->flags;
            new_regions[1].object = first->object;
            new_regions[1].offset = first->offset;
            insert_before(vmm, next_region(&new_regions[0]), &new_regions[1]);

            if (first->object) {
                vmo_ref(first->object);
                vmo_ref(first->object);
            }

            first->tail = addr - 1;
        } else if (first_needs_split || last_needs_split) {
            vm_region_t *new_regions = vmalloc(sizeof(*new_regions) * (!!first_needs_split + !!last_needs_split));
            if (unlikely(!new_regions)) {
                unreserve_pages(tot_extra_pages);
                mutex_unlock(&vmm->lock);
                return ERR_OUT_OF_MEMORY;
            }

            if (first_needs_split) {
                new_regions->head = addr;
                new_regions->tail = first->tail;
                new_regions->flags = first->flags;
                new_regions->object = first->object;
                new_regions->offset = first->offset;
                if (new_regions->object) vmo_ref(new_regions->object);
                insert_before(vmm, next_region(first), new_regions);

                first->tail = addr - 1;

                new_regions++;
            }

            if (last_needs_split) {
                new_regions->head = last->head;
                new_regions->tail = tail;
                new_regions->flags = last->flags;
                new_regions->object = last->object;
                new_regions->offset = last->offset;
                if (new_regions->object) vmo_ref(new_regions->object);
                insert_before(vmm, last, new_regions);

                tree_rem(vmm, last);
                last->head = tail + 1;
                tree_add(vmm, last);
            }
        }

        // do the operation
        vm_region_t *cur = prev;

        while (cur != NULL && cur->head <= tail) {
            vm_region_t *next = node_to_obj(vm_region_t, node, cur->node.next);

            ASSERT(cur->head >= addr);
            ASSERT(cur->tail <= tail);

            int new_flags = (cur->flags & ~VMM_PFLAG) | flags;
            size_t size = cur->tail - cur->head + 1;

            if (cur->flags & VMM_PFLAG) {
                if (flags & VMM_PFLAG) {
                    remap(cur->head, size, get_pmap_flags(flags));
                } else {
                    unmap(cur->head, size);
                    if (requires_reservation(cur->flags, cur->object)) unreserve_pages(size >> PAGE_SHIFT);
                }
            }

            cur->flags = new_flags;
            cur = next;
        }
    }

    mutex_unlock(&vmm->lock);
    return error;
}

int vmm_del(uintptr_t addr, size_t size) {
    if (size == 0) return ERR_INVALID_ARGUMENT;
    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return ERR_INVALID_ARGUMENT;
    addr &= ~PAGE_MASK;
    tail |= PAGE_MASK;
    if (tail >= MAX_USER_VIRT_ADDR) return ERR_INVALID_ARGUMENT;

    vmm_t *vmm = current_proc->vmm;

    mutex_lock(&vmm->lock);

    vm_region_t *prev = find_highest_below(vmm, addr);
    vm_region_t *next = node_to_obj(vm_region_t, node, prev ? prev->node.next : vmm->reg_list.first);
    int error = remove_overlapping(vmm, &prev, &next, addr, tail);

    mutex_unlock(&vmm->lock);
    return error;
}

vm_region_t *vmm_get(vmm_t *vmm, uintptr_t addr) {
    vm_region_t *cur = vmm->regions;

    while (cur != NULL) {
        if (cur->head <= addr && addr <= cur->tail) return cur;

        cur = addr < cur->head ? cur->left : cur->right;
    }

    return NULL;
}

void vmo_ref(vm_object_t *object) {
    __atomic_fetch_add(&object->references, 1, __ATOMIC_ACQ_REL);
}

void vmo_deref(vm_object_t *object) {
    if (__atomic_fetch_sub(&object->references, 1, __ATOMIC_ACQ_REL) == 1) {
        object->ops->free(object);
    }
}
