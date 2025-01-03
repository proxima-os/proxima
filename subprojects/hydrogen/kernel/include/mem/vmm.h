#ifndef HYDROGEN_MEM_VMM_H
#define HYDROGEN_MEM_VMM_H

#include "mem/pmap.h"
#include "sched/mutex.h"
#include "util/list.h"
#include <stdint.h>

#define VMM_READ (1u << 0)
#define VMM_WRITE (1u << 1)
#define VMM_EXEC (1u << 2)
#define VMM_EXACT (1u << 3)
#define VMM_PRIVATE (1u << 4)

typedef struct vm_object vm_object_t;
typedef struct vm_region vm_region_t;

typedef struct {
    void (*free)(vm_object_t *self);
    bool (*allow_flags)(vm_object_t *self, int flags);
    uint64_t (*get_base_pte)(vm_object_t *self, vm_region_t *region, size_t offset);
} vm_object_ops_t;

struct vm_object {
    const vm_object_ops_t *ops;
    size_t references;
    size_t size;
};

struct vm_region {
    vm_region_t *parent;
    vm_region_t *left;
    vm_region_t *right;
    list_node_t node;
    uintptr_t head;
    uintptr_t tail;
    int flags;

    vm_object_t *object;
    size_t offset;
};

typedef struct {
    size_t references;
    mutex_t lock;
    vm_region_t *regions;
    list_t reg_list;
    pmap_t *pmap;
} vmm_t;

int vmm_create(vmm_t **out);

int vmm_clone(vmm_t **out);

void vmm_ref(vmm_t *vmm);

void vmm_deref(vmm_t *vmm);

// must be called with irqs disabled
void vmm_switch(vmm_t *target);

int vmm_add(uintptr_t *addr, size_t size, int flags, vm_object_t *object, size_t offset);

int vmm_alter(uintptr_t addr, size_t size, int flags);

int vmm_del(uintptr_t addr, size_t size);

// you must own vmm->lock
vm_region_t *vmm_get(vmm_t *vmm, uintptr_t addr);

void vmo_ref(vm_object_t *object);

void vmo_deref(vm_object_t *object);

#endif // HYDROGEN_MEM_VMM_H
