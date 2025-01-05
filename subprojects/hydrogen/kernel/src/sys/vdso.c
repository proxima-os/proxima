#include "sys/vdso.h"
#include "proxima/compiler.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "sched/proc.h"
#include "util/panic.h"
#include <stdint.h>

extern const void __vdso_start;
extern const void __vdso_end;

static void vdso_free(UNUSED vm_object_t *self) {
    panic("tried to free vdso object");
}

static bool vdso_allow_flags(UNUSED vm_object_t *self, int flags) {
    return (flags & VMM_WRITE) == 0;
}

static uint64_t vdso_get_base_pte(UNUSED vm_object_t *self, UNUSED vm_region_t *region, size_t offset) {
    const void *base = offset ? &__vdso_start + (offset - PAGE_SIZE) : &vdso_info;
    return sym_to_phys(base);
}

static vm_object_ops_t vdso_ops = {
        .free = vdso_free,
        .allow_flags = vdso_allow_flags,
        .get_base_pte = vdso_get_base_pte,
};
vm_object_t vdso_object = {.ops = &vdso_ops, .references = 1};
static size_t vdso_image_size;

void init_vdso(void) {
    ASSERT((uintptr_t)&__vdso_start % 0x1000 == 0);
    ASSERT((uintptr_t)&vdso_info % 0x1000 == 0);

    vdso_image_size = &__vdso_end - &__vdso_start;
    vdso_object.size = vdso_image_size + PAGE_SIZE;
    ASSERT(vdso_object.size % PAGE_SIZE == 0);
}

bool is_address_in_vdso(uintptr_t address) {
    return address >= current_proc->vdso && address < (current_proc->vdso + vdso_image_size);
}

int map_vdso(uintptr_t *addr_out) {
    uintptr_t addr = 0;
    int error = vmm_add(&addr, vdso_object.size, VMM_READ | VMM_EXEC, &vdso_object, 0);
    if (error) return error;

    *addr_out = addr + PAGE_SIZE;
    return 0;
}
