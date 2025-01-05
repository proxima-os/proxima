#include "mem/pmap.h"
#include "asm/cr.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "cpu/lapic.h"
#include "hydrogen/error.h"
#include "mem/heap.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "proxima/compiler.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "string.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdatomic.h>
#include <stdint.h>

/**
 * This code is a mess. There's a lot of duplicated code, and it could look much nicer if I put the effort in.
 * However, I'm not going to bother doing that, because it works fine for now.
 *
 * Note that many of the functions here use 0x1000/0xfff/12 instead of PAGE_SIZE/PAGE_MASK/PAGE_SHIFT.
 * This is intentional, since these functions should keep working for those sizes even if PAGE_SHIFT is raised.
 */

#define PTE_TABLE_FLAGS (PTE_PRESENT | PTE_WRITABLE | PTE_USERSPACE | PTE_ACCESSED | PTE_DIRTY)

static uint64_t *kernel_pt;
static mutex_t kernel_pt_lock;

static void invlpg(uintptr_t vaddr) {
    asm("invlpg (%0)" ::"r"(vaddr) : "memory");
}

static mutex_t shootdown_lock;
static size_t shootdown_rem;

typedef struct {
    page_t *pages_to_free;
    bool shootdown;
    bool kernel;
} shootdown_ctx_t;

struct pmap {
    uint64_t *root_table;
    list_t cpus;
    spinlock_t cpus_lock;
};

static void handle_shootdown_ipi(UNUSED idt_frame_t *frame) {
    if (likely(pg_supported)) {
        size_t cr4 = read_cr4();
        write_cr4(cr4 & ~CR4_PGE);
        write_cr4(cr4);
    } else {
        write_cr3(read_cr3());
    }

    __atomic_fetch_sub(&shootdown_rem, 1, __ATOMIC_ACQ_REL);

    lapic_eoi();
}

static void shootdown_commit(shootdown_ctx_t *ctx) {
    if (num_cpus != 1 && ctx->shootdown) {
        mutex_lock(&shootdown_lock);

        if (!ctx->kernel) {
            shootdown_rem = 0;
            pmap_t *pmap = current_cpu.pmap;

            irq_state_t state = spin_lock(&pmap->cpus_lock);

            list_foreach(pmap->cpus, cpu_t, pmap_node, cur) {
                if (cur != current_cpu_ptr) {
                    __atomic_fetch_add(&shootdown_rem, 1, __ATOMIC_ACQ_REL);
                    lapic_send_ipi(cur, IPI_SHOOTDOWN);
                }
            }

            spin_unlock(&pmap->cpus_lock, state);
        } else {
            shootdown_rem = num_cpus - 1;
            lapic_send_ipi(NULL, IPI_SHOOTDOWN);
        }

        while (__atomic_load_n(&shootdown_rem, __ATOMIC_ACQUIRE) != 0) cpu_relax();

        mutex_unlock(&shootdown_lock);
    }

    union page *page = ctx->pages_to_free;

    while (page != NULL) {
        union page *next = page->anon.shootdown_next;
        free_page(page);
        page = next;
    }
}

static void *alloc_table(void) {
    void *ptr = kalloc(0x1000); // kalloc's alignment guarantees are strong enough for this
    if (ptr) memset(ptr, 0, 0x1000);
    return ptr;
}

static uint64_t get_accessed_entry(uint64_t *l4, size_t l4i, size_t l3i, size_t l2i, size_t l1i) {
    uint64_t l4e = l4[l4i];
    if (unlikely(!l4e)) return 0;
    uint64_t *l3 = phys_to_virt(l4e & PTE_ADDR);

    uint64_t l3e = l3[l3i];
    if (unlikely(!l3e || (l3e & PTE_HUGE))) return l3e;
    uint64_t *l2 = phys_to_virt(l3e & PTE_ADDR);

    uint64_t l2e = l2[l2i];
    if (unlikely(!l2e || (l2e & PTE_HUGE))) return l2e;
    uint64_t *l1 = phys_to_virt(l2e & PTE_ADDR);

    return l1[l1i];
}

static bool should_be_allowed(uint64_t entry, bool exec, bool write) {
    if (unlikely(!entry)) return false;
    if (unlikely(write && !(entry & PTE_WRITABLE))) return false;
    if (unlikely(exec && (entry & PTE_NX))) return false;
    return true;
}

_Static_assert(PAGE_SHIFT >= 12, "PAGE_SIZE must be at least 4k");
#define ENTRIES_PER_PAGE (1ul << (PAGE_SHIFT - 12))

static void handle_page_fault(idt_frame_t *frame) {
    bool was_present = frame->error_code & 1;
    bool was_write = frame->error_code & 2;
    bool was_user = frame->error_code & 4;
    ASSERT((frame->error_code & 8) == 0);
    bool was_exec = frame->error_code & 16;

    uintptr_t addr = read_cr2();
    size_t l4i = (addr >> 39) & 511;
    size_t l3i = (addr >> 30) & 511;
    size_t l2i = (addr >> 21) & 511;
    size_t l1i = (addr >> 12) & 511;

    vmm_t *vmm = current_proc->vmm;

    if (likely(l4i < 256)) {
        if (likely(frame->cs & 3) || likely(!smap_supported || (frame->rflags & 0x40000) != 0)) {
            mutex_lock(&vmm->lock);

            uint64_t l4e = vmm->pmap->root_table[l4i];

            if (likely(l4e)) {
                uint64_t *l3 = phys_to_virt(l4e & PTE_ADDR);
                uint64_t l3e = l3[l3i];

                if (likely(l3e)) {
                    uint64_t *l2 = phys_to_virt(l3e & PTE_ADDR);
                    uint64_t l2e = l2[l2i];

                    if (likely(l2e)) {
                        uint64_t *l1 = phys_to_virt(l2e & PTE_ADDR);
                        uint64_t l1e = l1[l1i];

                        if (should_be_allowed(l1e, was_exec, was_write)) {
                            invlpg(addr);
                            mutex_unlock(&vmm->lock);
                            return;
                        }

                        if (l1e & PTE_COW) {
                            l1i &= ~(ENTRIES_PER_PAGE - 1);
                            l1e = l1[l1i];
                            ASSERT(l1e & PTE_COW);

                            page_t *src = phys_to_page(l1e & PTE_ADDR);

                            if (__atomic_load_n(&src->anon.references, __ATOMIC_ACQUIRE) == 1) {
                                l1e = (l1e & ~PTE_COW) | PTE_WRITABLE;
                            } else {
                                page_t *dest = alloc_page();
                                dest->anon.references = 1;
                                dest->anon.autounreserve = false;
                                memcpy(page_to_virt(dest), page_to_virt(src), PAGE_SIZE);
                                l1e = (l1e & ~(PTE_ADDR | PTE_COW)) | page_to_phys(dest) | PTE_WRITABLE;

                                UNUSED size_t new_ref = __atomic_sub_fetch(&src->anon.references, 1, __ATOMIC_ACQ_REL);
                                ASSERT(new_ref != 0);
                            }

                            for (size_t i = 0; i < ENTRIES_PER_PAGE; i++) {
                                l1[l1i++] = l1e;
                                invlpg(addr);
                                addr += 0x1000;
                                l1e += 0x1000;
                            }

                            mutex_unlock(&vmm->lock);
                            return;
                        }

                        if (!was_present) {
                            vm_region_t *region = vmm_get(vmm, addr);

                            if (likely(region != NULL && (region->flags & (VMM_READ | VMM_WRITE | VMM_EXEC)) != 0)) {
                                uint64_t pte;

                                if (region->object) {
                                    size_t offset = region->offset + ((addr - region->head) & ~PAGE_MASK);
                                    pte = region->object->ops->get_base_pte(region->object, region, offset);
                                } else {
                                    page_t *page = alloc_page();
                                    page->anon.references = 1;
                                    page->anon.autounreserve = false;
                                    memset(page_to_virt(page), 0, PAGE_SIZE);
                                    pte = page_to_phys(page) | PTE_ANON;
                                }

                                if (pte) {
                                    pte |= PTE_DIRTY | PTE_ACCESSED | PTE_USERSPACE | PTE_PRESENT;

                                    if ((region->flags & VMM_WRITE) && ~(pte & PTE_COW)) pte |= PTE_WRITABLE;
                                    if (!(region->flags & VMM_EXEC) && nx_supported) pte |= PTE_NX;

                                    l1i &= ~(ENTRIES_PER_PAGE - 1);

                                    for (size_t i = 0; i < ENTRIES_PER_PAGE; i++) {
                                        l1[l1i++] = pte;
                                        pte += 0x1000;
                                    }

                                    mutex_unlock(&vmm->lock);
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            mutex_unlock(&vmm->lock);
        }
    } else if (!was_user) {
        uint64_t *real_l4 = vmm->pmap->root_table;

        mutex_lock(&kernel_pt_lock);

        if (kernel_pt[l4i] != real_l4[l4i]) {
            real_l4[l4i] = kernel_pt[l4i];
            mutex_unlock(&kernel_pt_lock);
            return;
        }

        uint64_t entry = get_accessed_entry(kernel_pt, l4i, l3i, l2i, l1i);
        if (should_be_allowed(entry, was_exec, was_write)) {
            invlpg(addr);
            mutex_unlock(&kernel_pt_lock);
            return;
        }

        mutex_unlock(&kernel_pt_lock);
    }

    handle_fatal_exception(frame);
}

void init_pmap(void) {
    idt_install(14, handle_page_fault);
    idt_install(IPI_SHOOTDOWN, handle_shootdown_ipi);

    kernel_pt = alloc_table();
    if (kernel_pt == NULL) panic("failed to allocate kernel page table");
}

int pmap_create(pmap_t **out) {
    pmap_t *pmap = vmalloc(sizeof(*pmap));
    if (unlikely(!pmap)) return ERR_OUT_OF_MEMORY;
    memset(pmap, 0, sizeof(*pmap));

    pmap->root_table = alloc_table();
    if (unlikely(!pmap->root_table)) {
        vmfree(pmap, sizeof(*pmap));
        return ERR_OUT_OF_MEMORY;
    }
    memcpy(&pmap->root_table[256], &kernel_pt[256], 0x800);

    *out = pmap;
    return 0;
}

int pmap_clone(pmap_t **out) {
    int error = pmap_create(out);
    if (unlikely(error)) return error;

    uint64_t *l4s = current_cpu.pmap->root_table;
    uint64_t *l4d = (*out)->root_table;

    shootdown_ctx_t ctx = {};

    for (size_t l4i = 0; l4i < 256; l4i++) {
        uint64_t l4e = l4s[l4i];
        if (!l4e) continue;

        uint64_t *l3s = phys_to_virt(l4e & PTE_ADDR);
        uint64_t *l3d = alloc_table();
        if (!l3d) goto err;
        l4d[l4i] = virt_to_phys(l3d) | PTE_TABLE_FLAGS;

        for (size_t l3i = 0; l3i < 512; l3i++) {
            uint64_t l3e = l3s[l3i];
            if (!l3e) continue;

            uint64_t *l2s = phys_to_virt(l3e & PTE_ADDR);
            uint64_t *l2d = alloc_table();
            if (!l2d) goto err;
            l3d[l3i] = virt_to_phys(l2d) | PTE_TABLE_FLAGS;

            for (size_t l2i = 0; l2i < 512; l2i++) {
                uint64_t l2e = l2s[l2i];
                if (!l2e) continue;

                uint64_t *l1s = phys_to_virt(l2e & PTE_ADDR);
                uint64_t *l1d = alloc_table();
                if (!l1d) goto err;
                l2d[l2i] = virt_to_phys(l1d) | PTE_TABLE_FLAGS;

                for (size_t l1i = 0; l1i < 512; l1i++) {
                    uint64_t l1e = l1s[l1i];

                    if (l1e & PTE_ANON) {
                        if ((l1e & (PTE_ADDR & PAGE_MASK)) == 0) {
                            __atomic_fetch_add(&phys_to_page(l1e & PTE_ADDR)->anon.references, 1, __ATOMIC_ACQ_REL);
                        }

                        if (l1e & PTE_WRITABLE) {
                            l1e &= ~PTE_WRITABLE;
                            l1e |= PTE_COW;
                            l1s[l1i] = l1e;
                            invlpg((l4i << 39) | (l3i << 30) | (l2i << 21) | (l1i << 12));
                            ctx.shootdown = true;
                        }
                    }

                    l1d[l1i] = l1e;
                }
            }
        }
    }

    shootdown_commit(&ctx);

    return 0;
err:
    pmap_destroy(*out);
    return ERR_OUT_OF_MEMORY;
}

void pmap_switch(pmap_t *target) {
    if (num_cpus != 1) {
        pmap_t *old = current_cpu.pmap;

        if (old) {
            spin_lock_noirq(&old->cpus_lock);
            list_remove(&old->cpus, &current_cpu_ptr->pmap_node);
            spin_unlock_noirq(&old->cpus_lock);
        }

        if (target) {
            spin_lock_noirq(&target->cpus_lock);
            list_insert_tail(&target->cpus, &current_cpu_ptr->pmap_node);
            spin_unlock_noirq(&target->cpus_lock);
        }

        current_cpu.pmap = target;
    }

    write_cr3(virt_to_phys(target ? target->root_table : kernel_pt));
}

void pmap_destroy(pmap_t *pmap) {
    ASSERT(list_is_empty(&pmap->cpus));

    uint64_t *l4 = pmap->root_table;

    for (size_t l4i = 0; l4i < 256; l4i++) {
        uint64_t l4e = l4[l4i];
        if (!l4e) continue;
        uint64_t *l3 = phys_to_virt(l4e & PTE_ADDR);

        for (size_t l3i = 0; l3i < 512; l3i++) {
            uint64_t l3e = l3[l3i];
            if (!l3e) continue;
            uint64_t *l2 = phys_to_virt(l3e & PTE_ADDR);

            for (size_t l2i = 0; l2i < 512; l2i++) {
                uint64_t l2e = l2[l2i];
                if (!l2e) continue;
                uint64_t *l1 = phys_to_virt(l2e & PTE_ADDR);

                for (size_t l1i = 0; l1i < 512; l1i++) {
                    uint64_t l1e = l1[l1i];

                    if ((l1e & (PTE_ANON | (PTE_ADDR & PAGE_MASK))) == PTE_ANON) {
                        page_t *page = phys_to_page(l1e & PTE_ADDR);

                        if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
                            if (page->anon.autounreserve) free_page_now(page);
                            else free_page(page);
                        }
                    }
                }

                kfree(l1, 0x1000);
            }

            kfree(l2, 0x1000);
        }

        kfree(l3, 0x1000);
    }

    kfree(l4, 0x1000);
}

void switch_to_kernel_mappings(void) {
    if (pg_supported) write_cr4(read_cr4() & ~CR4_PGE);
    write_cr3(virt_to_phys(kernel_pt));
    if (pg_supported) write_cr4(read_cr4() | CR4_PGE);
}

static uint64_t *get_l4(size_t l4i_start) {
    if (likely(l4i_start < 256)) {
        return current_proc->vmm->pmap->root_table;
    } else {
        mutex_lock(&kernel_pt_lock);
        return kernel_pt;
    }
}

static void unlock_if_necessary(size_t l4i_start) {
    if (unlikely(l4i_start >= 256)) mutex_unlock(&kernel_pt_lock);
}

int prepare_map(uintptr_t vaddr, size_t size) {
    if ((vaddr | size) & 0xfff) return ERR_INVALID_ARGUMENT;
    if (size == 0) return 0;

    uintptr_t end = vaddr + (size - 1);
    if (end < vaddr) return ERR_INVALID_ARGUMENT;

    size_t l4i_start = (vaddr >> 39) & 511;
    size_t l3i_start = (vaddr >> 30) & 511;
    size_t l2i_start = (vaddr >> 21) & 511;

    size_t l4i_end = (end >> 39) & 511;
    size_t l3i_end = 511;
    size_t l2i_end = 511;

    if ((l4i_start & 256) != (l4i_end & 256)) return ERR_INVALID_ARGUMENT;

    uint64_t *l4 = get_l4(l4i_start);

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

    unlock_if_necessary(l4i_start);
    return 0;
err:
    unlock_if_necessary(l4i_start);
    return ERR_OUT_OF_MEMORY;
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

    uint64_t *l4 = get_l4(l4i_start);

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

    unlock_if_necessary(l4i_start);
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

    ASSERT(l4i_start >= 256);

    uint64_t flags = PTE_ANON | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

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
                        page_t *page = alloc_page();
                        cur_phys = page_to_phys(page);
                        cur_phys_rem = PAGE_SIZE / 4096;
                        page->anon.references = 1;
                        page->anon.autounreserve = false;
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

    shootdown_ctx_t shootdown = {.kernel = l4i_start & 256};

    uint64_t *l4 = get_l4(l4i_start);

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

                            if (!(l1e & PTE_NX) && (mask & PTE_NX)) shootdown.shootdown = true;
                            else if ((l1e & PTE_WRITABLE) && !(mask & PTE_WRITABLE)) shootdown.shootdown = true;
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

    shootdown_commit(&shootdown);
    unlock_if_necessary(l4i_start);
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

    shootdown_ctx_t shootdown = {.kernel = l4i_start & 256};
    uint64_t *l4 = get_l4(l4i_start);

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
                        shootdown.shootdown = true;

                        if ((l1e & (PTE_ANON | (PTE_ADDR & PAGE_MASK))) == PTE_ANON) {
                            page_t *page = phys_to_page(l1e & PTE_ADDR);

                            if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
                                page->anon.shootdown_next = shootdown.pages_to_free;
                                shootdown.pages_to_free = page;
                            }
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

    shootdown_commit(&shootdown);
    unlock_if_necessary(l4i_start);
}

void extend_hhdm(uint64_t paddr, size_t size) {
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

    uint64_t pte = paddr | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    if (pg_supported) pte |= PTE_GLOBAL;
    if (nx_supported) pte |= PTE_NX;

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
            } else if (gb_pages_supported && l2i_start == 0 && l2i_end == 511 && (pte & (PTE_ADDR & 0x3fffffff)) == 0) {
                ASSERT(l3[l3i] == 0);
                l3[l3i] = pte | PTE_HUGE;
                pte += 0x40000000;
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
                } else if (l1i_start == 0 && l1i_end == 511 && (pte & (PTE_ADDR & 0x1fffff)) == 0) {
                    ASSERT(l2[l2i] == 0);
                    l2[l2i] = pte | PTE_HUGE;
                    pte += 0x200000;
                    continue;
                } else {
                    l1 = alloc_table();
                    if (!l1) goto err;
                    l2[l2i] = virt_to_phys(l1) | PTE_TABLE_FLAGS;
                }

                for (size_t l1i = l1i_start; l1i <= l1i_end; l1i++) {
                    ASSERT(l1[l1i] == 0);
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
    return;

err:
    panic("not enough memory to extend hhdm");
}
