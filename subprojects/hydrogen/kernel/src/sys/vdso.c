#include "sys/vdso.h"
#include "compiler.h"
#include "mem/heap.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "string.h"
#include "util/panic.h"
#include <stdint.h>

extern const void __vdso_start;
extern const void __vdso_end;

static void vdso_free(UNUSED vm_object_t *self) {
    panic("tried to free vdso object");
}

static bool vdso_allow_flags(UNUSED vm_object_t *self, int flags) {
    return (flags & VMM_WRITE) == 0 || (flags & VMM_PRIVATE) != 0;
}

static uint64_t vdso_get_base_pte(UNUSED vm_object_t *self, vm_region_t *region, size_t offset) {
    const void *base = offset ? &__vdso_start + (offset - PAGE_SIZE) : &vdso_info;

    if (region->flags & VMM_PRIVATE) {
        page_t *page = alloc_page();
        page->anon.references = 1;
        memcpy(page_to_virt(page), base, PAGE_SIZE);
        return page_to_phys(page) | PTE_ANON;
    }

    return sym_to_phys(base);
}

static vm_object_ops_t vdso_ops = {
        .free = vdso_free,
        .allow_flags = vdso_allow_flags,
        .get_base_pte = vdso_get_base_pte,
};
static vm_object_t vdso_object = {.ops = &vdso_ops, .references = 1};

void init_vdso(void) {
    ASSERT((uintptr_t)&__vdso_start % 0x1000 == 0);
    ASSERT((uintptr_t)&vdso_info % 0x1000 == 0);

    vdso_object.size = &__vdso_end - &__vdso_start + PAGE_SIZE;
    ASSERT(vdso_object.size % PAGE_SIZE == 0);
}

int map_vdso(uintptr_t *addr_out) {
    uintptr_t addr = 0;
    int error = vmm_add(&addr, vdso_object.size, VMM_READ | VMM_EXEC, &vdso_object, 0);
    if (error) return error;

    *addr_out = addr + PAGE_SIZE;
    return 0;
}
