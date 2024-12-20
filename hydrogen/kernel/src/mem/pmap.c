#include "mem/pmap.h"
#include "asm/cr.h"
#include "cpu/cpu.h"
#include "errno.h"
#include "mem/heap.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include "string.h"
#include "util/panic.h"
#include <stdint.h>

/**
 * This code is a mess. There's a lot of duplicated code, and it could look much nicer if I put the effort in.
 * However, I'm not going to bother doing that, because it works fine for now.
 *
 * Note that many of the functions here use 0x1000/0xfff/12 instead of PAGE_SIZE/PAGE_MASK/PAGE_SHIFT.
 * This is intentional, since these functions should keep working for those sizes even if PAGE_SHIFT is raised.
 */

#define PTE_PRESENT 1
#define PTE_WRITABLE 2
#define PTE_USERSPACE 4
#define PTE_ACCESSED 0x20
#define PTE_DIRTY 0x40
#define PTE_HUGE 0x80
#define PTE_GLOBAL 0x100
#define PTE_ADDR 0xffffffffff000
#define PTE_NX 0x8000000000000000

#define PTE_TABLE_FLAGS (PTE_PRESENT | PTE_WRITABLE | PTE_USERSPACE | PTE_ACCESSED | PTE_DIRTY)

static uint64_t *kernel_pt;
static mutex_t kernel_pt_lock;

static void invlpg(uintptr_t vaddr) {
    asm("invlpg (%0)" ::"r"(vaddr) : "memory");
}

static void *alloc_table(void) {
    void *ptr = kalloc(0x1000); // kalloc's alignment guarantees are strong enough for this
    if (ptr) memset(ptr, 0, 0x1000);
    return ptr;
}

void init_pmap(void) {
    kernel_pt = alloc_table();
    if (kernel_pt == NULL) panic("failed to allocate kernel page table");
}

void switch_to_kernel_mappings(void) {
    if (pg_supported) write_cr4(read_cr4() & ~CR4_PGE);
    write_cr3(virt_to_phys(kernel_pt));
    if (pg_supported) write_cr4(read_cr4() | CR4_PGE);
}

int prepare_map(uintptr_t vaddr, size_t size) {
    if ((vaddr | size) & 0xfff) return EINVAL;
    if (size == 0) return 0;

    uintptr_t end = vaddr + (size - 1);
    if (end < vaddr) return EINVAL;

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;

    if ((l4i_start & 256) != (l4i_end & 256)) return EINVAL;

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t l4e = l4[l4i];
        uint64_t *l3;

        if (l4e) {
            l3 = phys_to_virt(l4e & PTE_ADDR);
        } else {
            l3 = alloc_table();
            if (!l3) goto err;
            l4[l4i] = virt_to_phys(l3) | PTE_TABLE_FLAGS;
        }

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t l3e = l3[l3i];
            uint64_t *l2;

            if (l3e) {
                l2 = phys_to_virt(l3e & PTE_ADDR);
            } else {
                l2 = alloc_table();
                if (!l2) goto err;
                l3[l3i] = virt_to_phys(l2) | PTE_TABLE_FLAGS;
            }

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                uint64_t l2e = l2[l2i];

                if (l2e == 0) {
                    void *l1 = alloc_table();
                    if (!l1) goto err;
                    l2[l2i] = virt_to_phys(l1) | PTE_TABLE_FLAGS;
                }
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
    return 0;
err:
    mutex_unlock(&kernel_pt_lock);
    return ENOMEM;
}

void do_map(uintptr_t vaddr, uint64_t paddr, size_t size, int flags, cache_mode_t mode) {
    ASSERT(((vaddr | paddr | size) & 0xfff) == 0);
    if (size == 0) return;

    uintptr_t end = vaddr + (size - 1);
    ASSERT(end > vaddr);

    ASSERT(paddr < paddr + (size - 1));
    ASSERT(paddr + (size - 1) <= cpu_paddr_mask);

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;
    size_t l1i_start = (vaddr >> 12) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;
    size_t l1i_end = 511;

    ASSERT((l4i_start & 256) == (l4i_end & 256));

    uint64_t pte = paddr | ((mode & 4) << 5) | PTE_DIRTY | PTE_ACCESSED | ((mode & 3) << 3) | PTE_PRESENT;

    if (l4i_start < 256) pte |= PTE_USERSPACE;
    else if (pg_supported) pte |= PTE_GLOBAL;

    if (flags & PMAP_WRITE) pte |= PTE_WRITABLE;
    if (!(flags & PMAP_EXEC) && nx_supported) pte |= PTE_NX;

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t *l3 = phys_to_virt(l4[l4i] & PTE_ADDR);

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t *l2 = phys_to_virt(l3[l3i] & PTE_ADDR);

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                if (l4i == l4i_end && l3i == l3i_end && l2i == l2i_end) l1i_end = (end >> 12) & 511;

                uint64_t *l1 = phys_to_virt(l2[l2i] & PTE_ADDR);

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    ASSERT(l1[l1i] == 0 || l1[l1i] == pte);
                    l1[l1i] = pte;
                    pte += 0x1000;
                }

                l1i_start = 0;
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
}

_Static_assert(PAGE_SIZE >= 4096, "PAGE_SIZE is not a multiple of 4096");

void alloc_and_map(uintptr_t vaddr, size_t size) {
    ASSERT((vaddr & 0xfff) == 0);
    ASSERT((size & PAGE_MASK) == 0);

    if (size == 0) return;

    uintptr_t end = vaddr + (size - 1);
    ASSERT(end > vaddr);

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;
    size_t l1i_start = (vaddr >> 12) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;
    size_t l1i_end = 511;

    ASSERT((l4i_start & 256) == (l4i_end & 256));

    uint64_t flags = PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    if (nx_supported) flags |= PTE_NX;

    if (l4i_start < 256) flags |= PTE_USERSPACE;
    else if (pg_supported) flags |= PTE_GLOBAL;

    uint64_t cur_phys = 0;
    size_t cur_phys_rem = 0;

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t *l3 = phys_to_virt(l4[l4i] & PTE_ADDR);

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t *l2 = phys_to_virt(l3[l3i] & PTE_ADDR);

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                if (l4i == l4i_end && l3i == l3i_end && l2i == l2i_end) l1i_end = (end >> 12) & 511;

                uint64_t *l1 = phys_to_virt(l2[l2i] & PTE_ADDR);

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    if (cur_phys_rem == 0) {
                        cur_phys = page_to_phys(alloc_page());
                        cur_phys_rem = PAGE_SIZE / 4096;
                    }

                    uint64_t pte = cur_phys | flags;
                    cur_phys += 4096;
                    cur_phys_rem -= 1;

                    ASSERT(l1[l1i] == 0 || l1[l1i] == pte);
                    l1[l1i] = pte;
                }

                l1i_start = 0;
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
}

void remap(uintptr_t vaddr, size_t size, int flags) {
    ASSERT(((vaddr | size) & 0xfff) == 0);
    if (size == 0) return;

    uintptr_t end = vaddr + (size - 1);
    ASSERT(end > vaddr);

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;
    size_t l1i_start = (vaddr >> 12) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;
    size_t l1i_end = 511;

    ASSERT((l4i_start & 256) == (l4i_end & 256));

    uint64_t mask = 0;

    if (flags & PMAP_WRITE) mask |= PTE_WRITABLE;
    if (!(flags & PMAP_EXEC) && nx_supported) mask |= PTE_NX;

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t *l3 = phys_to_virt(l4[l4i] & PTE_ADDR);

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t *l2 = phys_to_virt(l3[l3i] & PTE_ADDR);

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                if (l4i == l4i_end && l3i == l3i_end && l2i == l2i_end) l1i_end = (end >> 12) & 511;

                uint64_t *l1 = phys_to_virt(l2[l2i] & PTE_ADDR);

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    uint64_t l1e = l1[l1i];

                    if (l1e != 0) {
                        uint64_t new_entry = (l1e & ~(PTE_NX | PTE_WRITABLE)) | mask;

                        if (new_entry != l1e) {
                            l1[l1i] = new_entry;
                            invlpg(vaddr);
                        }
                    }

                    vaddr += 0x1000;
                }

                l1i_start = 0;
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
}

void unmap(uintptr_t vaddr, size_t size) {
    ASSERT(((vaddr | size) & 0xfff) == 0);
    if (size == 0) return;

    uintptr_t end = vaddr + (size - 1);
    ASSERT(end > vaddr);

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;
    size_t l1i_start = (vaddr >> 12) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;
    size_t l1i_end = 511;

    ASSERT((l4i_start & 256) == (l4i_end & 256));

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t *l3 = phys_to_virt(l4[l4i] & PTE_ADDR);

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t *l2 = phys_to_virt(l3[l3i] & PTE_ADDR);

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                if (l4i == l4i_end && l3i == l3i_end && l2i == l2i_end) l1i_end = (end >> 12) & 511;

                uint64_t *l1 = phys_to_virt(l2[l2i] & PTE_ADDR);

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    uint64_t l1e = l1[l1i];

                    if (l1e != 0) {
                        l1[l1i] = 0;
                        invlpg(vaddr);
                    }

                    vaddr += 0x1000;
                }

                l1i_start = 0;
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
}

void unmap_and_free(uintptr_t vaddr, size_t size) {
    ASSERT((vaddr & 0xfff) == 0);
    ASSERT((size & PAGE_MASK) == 0);

    if (size == 0) return;

    uintptr_t end = vaddr + (size - 1);
    ASSERT(end > vaddr);

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;
    size_t l1i_start = (vaddr >> 12) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;
    size_t l1i_end = 511;

    ASSERT((l4i_start & 256) == (l4i_end & 256));

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t *l3 = phys_to_virt(l4[l4i] & PTE_ADDR);

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t *l2 = phys_to_virt(l3[l3i] & PTE_ADDR);

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                if (l4i == l4i_end && l3i == l3i_end && l2i == l2i_end) l1i_end = (end >> 12) & 511;

                uint64_t *l1 = phys_to_virt(l2[l2i] & PTE_ADDR);

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    uint64_t l1e = l1[l1i];

                    if (l1e != 0) {
                        l1[l1i] = 0;
                        invlpg(vaddr);

                        uint64_t phys = l1e & PTE_ADDR;
                        if ((phys & PAGE_MASK) == 0) free_page(phys_to_page(phys));
                    }

                    vaddr += 0x1000;
                }

                l1i_start = 0;
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
}

void extend_hhdm(uint64_t paddr, size_t size, cache_mode_t mode) {
    if (size == 0) return;

    uint64_t pend = (paddr + size + 0xfff) & ~0xfff;
    paddr &= ~0xfff;
    size = pend - paddr;

    uintptr_t vaddr = (uintptr_t)phys_to_virt(paddr);
    uintptr_t end = vaddr + (size - 1);
    if (end < vaddr) panic("wrapped around address space while extending hhdm");

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;
    size_t l1i_start = (vaddr >> 12) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;
    size_t l1i_end = 511;

    uint64_t base_flags = PTE_DIRTY | PTE_ACCESSED | ((mode & 3) << 3) | PTE_WRITABLE | PTE_PRESENT;

    if (pg_supported) base_flags |= PTE_GLOBAL;
    if (nx_supported) base_flags |= PTE_NX;

    uint64_t norm_flags = ((mode & 4) << 5) | base_flags;
    uint64_t huge_flags = ((mode & 4) << 10) | PTE_HUGE | base_flags;

    uint64_t *l4 = kernel_pt;
    mutex_lock(&kernel_pt_lock);

    for (size_t l4i = l4i_start; l4i <= l4i_end; l4i++) {
        if (l4i == l4i_end) l3i_end = (end >> 30) & 511;

        uint64_t l4e = l4[l4i];
        uint64_t *l3;

        if (l4e) {
            l3 = phys_to_virt(l4e & PTE_ADDR);
        } else {
            l3 = alloc_table();
            if (!l3) goto err;
            l4[l4i] = virt_to_phys(l3) | PTE_TABLE_FLAGS;
        }

        for (size_t l3i = l3i_start; l3i <= l3i_end; l3i++) {
            if (l4i == l4i_end && l3i == l3i_end) l2i_end = (end >> 21) & 511;

            uint64_t l3e = l3[l3i];
            uint64_t *l2;

            if (l3e) {
                l2 = phys_to_virt(l3e & PTE_ADDR);
            } else if (gb_pages_supported && l2i_start == 0 && l2i_end == 511 && (paddr & 0x3fffffff) == 0) {
                if (l3[l3i] == 0) l3[l3i] = paddr | huge_flags;
                paddr += 0x40000000;
                continue;
            } else {
                l2 = alloc_table();
                if (!l2) goto err;
                l3[l3i] = virt_to_phys(l2) | PTE_TABLE_FLAGS;
            }

            for (size_t l2i = l2i_start; l2i <= l2i_end; l2i++) {
                if (l4i == l4i_end && l3i == l3i_end && l2i == l2i_end) l1i_end = (end >> 12) & 511;

                uint64_t l2e = l2[l2i];
                uint64_t *l1;

                if (l2e) {
                    l1 = phys_to_virt(l2e & PTE_ADDR);
                } else if (l1i_start == 0 && l1i_end == 511 && (paddr & 0x1fffff) == 0) {
                    if (l2[l2i] == 0) l2[l2i] = paddr | huge_flags;
                    paddr += 0x200000;
                    continue;
                } else {
                    l1 = alloc_table();
                    if (!l1) goto err;
                    l2[l2i] = virt_to_phys(l1) | PTE_TABLE_FLAGS;
                }

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    if (l1[l1i] == 0) l1[l1i] = paddr | norm_flags;
                    paddr += 0x1000;
                }

                l1i_start = 0;
            }

            l2i_start = 0;
        }

        l3i_start = 0;
    }

    mutex_unlock(&kernel_pt_lock);
    return;

err:
    panic("not enough memory to extend hhdm");
}
