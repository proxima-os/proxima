#include "mem/pmm.h"
#include "proxima/compiler.h"
#include "cpu/cpu.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "sched/mutex.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

void *hhdm_start;
page_t *page_array;

static uint64_t kernel_phys;
static struct limine_memmap_response *mmap;

static page_t *free_pages;
static pmm_stats_t pmm_stats;
static mutex_t pmm_lock;

static uint64_t max_phys_addr;

extern const void _start;
extern const void _erodata;
extern const void _etext;
extern const void _end;

static void free_regions(uint64_t type) {
    for (uint64_t i = 0; i < mmap->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap->entries[i];
        if (entry->length == 0) continue;

        if (entry->type == type) {
            uint64_t aligned_start = (entry->base + PAGE_MASK) & ~PAGE_MASK;
            uint64_t aligned_end = (entry->base + entry->length) & ~PAGE_MASK;
            if (aligned_start > max_phys_addr) aligned_end = max_phys_addr;

            if (aligned_start < aligned_end) {
                page_t *page = phys_to_page(aligned_start);
                page->free.next = free_pages;
                page->free.count = (aligned_end - aligned_start) >> PAGE_SHIFT;
                free_pages = page;

                pmm_stats.total += page->free.count;
                pmm_stats.avail += page->free.count;
                pmm_stats.free += page->free.count;
            }
        }
    }
}

static void map_segment(const void *start, const void *end, int flags) {
    uint64_t paddr = sym_to_phys(start);
    size_t size = end - start;

    int error = prepare_map((uintptr_t)start, size);
    if (error) panic("failed to map kernel segment (%d)", error);
    do_map((uintptr_t)start, paddr, size, flags, CACHE_WRITEBACK);
}

static void add_vmm_range(uintptr_t start, uintptr_t end) {
    start = (start + PAGE_MASK) & ~PAGE_MASK;
    end = (end - PAGE_MASK) | PAGE_MASK;

    if (start >= end) return;

    int error = vmem_add_range(&kvmm, start, end - start + 1);
    if (error) panic("failed to add range to kernel vmm (%d)", error);
}

void init_pmm(void) {
    static LIMINE_REQ struct limine_executable_address_request kaddr_req = {.id = LIMINE_EXECUTABLE_ADDRESS_REQUEST};
    static LIMINE_REQ struct limine_hhdm_request hhdm_req = {.id = LIMINE_HHDM_REQUEST};
    static LIMINE_REQ struct limine_memmap_request mmap_req = {.id = LIMINE_MEMMAP_REQUEST};

    if (!kaddr_req.response) panic("no response to kernel address request");
    if (!hhdm_req.response) panic("no response to hhdm request");
    if (!mmap_req.response) panic("no response to memory map request");

    kernel_phys = kaddr_req.response->physical_base + ((uintptr_t)&_start - kaddr_req.response->virtual_base);
    hhdm_start = (void *)hhdm_req.response->offset;
    mmap = mmap_req.response;

    for (uint64_t i = mmap->entry_count; i > 0; i--) {
        struct limine_memmap_entry *entry = mmap->entries[i - 1];
        if (entry->length == 0) continue;

        if (entry->type == LIMINE_MEMMAP_USABLE || entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) {
            max_phys_addr = entry->base + entry->length;
            break;
        }
    }

    if (max_phys_addr == 0) panic("no usable regions in memory map");
    if (max_phys_addr > cpu_paddr_mask) max_phys_addr = cpu_paddr_mask + 1;

    uint64_t max_hhdm_size;
    if (hhdm_start < &_start) max_hhdm_size = &_start - hhdm_start;
    else max_hhdm_size = UINTPTR_MAX - (uintptr_t)hhdm_start + 1;

    uint64_t hhdm_size = (UINTPTR_MAX - MIN_KERNEL_VIRT_ADDR + 1) / 2;
    if (hhdm_size > cpu_paddr_mask) hhdm_size = cpu_paddr_mask + 1;
    if (hhdm_size > max_hhdm_size) hhdm_size = max_hhdm_size;

    if (max_phys_addr > hhdm_size) max_phys_addr = hhdm_size;

    max_phys_addr &= ~PAGE_MASK;

    size_t page_array_size = (max_phys_addr >> PAGE_SHIFT) * sizeof(page_t);

    for (uint64_t i = mmap->entry_count; i > 0; i--) {
        struct limine_memmap_entry *entry = mmap->entries[i - 1];
        if (entry->length < page_array_size) continue;

        if (entry->type == LIMINE_MEMMAP_USABLE || entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) {
            page_array = phys_to_virt(entry->base + entry->length - page_array_size);
            entry->length -= page_array_size;
            break;
        }
    }

    free_regions(LIMINE_MEMMAP_USABLE);
    init_pmap();

    if (hhdm_start < &_start) {
        add_vmm_range(MIN_KERNEL_VIRT_ADDR, (uintptr_t)hhdm_start - 1);
        add_vmm_range((uintptr_t)hhdm_start + hhdm_size, (uintptr_t)&_start - 1);
        add_vmm_range((uintptr_t)&_end, UINTPTR_MAX);
    } else {
        add_vmm_range(MIN_KERNEL_VIRT_ADDR, (uintptr_t)&_start - 1);
        add_vmm_range((uintptr_t)&_end, (uintptr_t)hhdm_start - 1);
        add_vmm_range((uintptr_t)hhdm_start + hhdm_size, UINTPTR_MAX);
    }

    uint64_t map_start = 0;
    uint64_t map_end = 0;

    for (uint64_t i = 0; i < mmap->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap->entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) continue;

        uint64_t length = entry->length;
        if (entry->base + length == virt_to_phys(page_array)) length += page_array_size;
        if (entry->length == 0) continue;

        if (map_end != entry->base) {
            extend_hhdm(map_start, map_end - map_start);
            map_start = map_end = entry->base;
        }

        map_end += length;
    }

    extend_hhdm(map_start, map_end - map_start);

    map_segment(&_start, &_erodata, 0);
    map_segment(&_erodata, &_etext, PMAP_EXEC);
    map_segment(&_etext, &_end, PMAP_WRITE);

    map_print();

    switch_to_kernel_mappings();
}

void reclaim_loader_memory(void) {
    mutex_lock(&pmm_lock);

    if (mmap != NULL) {
        free_regions(LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE);
        mmap = NULL;
    }

    mutex_unlock(&pmm_lock);
}

pmm_stats_t get_pmm_stats(void) {
    mutex_lock(&pmm_lock);
    pmm_stats_t stats = pmm_stats;
    mutex_unlock(&pmm_lock);
    return stats;
}

uint64_t sym_to_phys(const void *sym) {
    return kernel_phys + (sym - &_start);
}

bool reserve_pages(size_t count) {
    mutex_lock(&pmm_lock);
    bool success = count <= pmm_stats.avail;
    if (likely(success)) pmm_stats.avail -= count;
    mutex_unlock(&pmm_lock);
    return success;
}

void unreserve_pages(size_t count) {
    mutex_lock(&pmm_lock);
    pmm_stats.avail += count;
    mutex_unlock(&pmm_lock);
}

page_t *alloc_page(void) {
    mutex_lock(&pmm_lock);

    page_t *base = free_pages;
    size_t index = --base->free.count;
    if (unlikely(index == 0)) free_pages = base->free.next;

    pmm_stats.free -= 1;

    mutex_unlock(&pmm_lock);
    return base + index;
}

void free_page(page_t *page) {
    page->free.count = 1;

    mutex_lock(&pmm_lock);
    page->free.next = free_pages;
    free_pages = page;
    pmm_stats.free += 1;
    mutex_unlock(&pmm_lock);
}

page_t *alloc_page_now(void) {
    mutex_lock(&pmm_lock);

    if (unlikely(pmm_stats.avail == 0)) {
        mutex_unlock(&pmm_lock);
        return NULL;
    }

    pmm_stats.avail -= 1;
    pmm_stats.free -= 1;

    page_t *base = free_pages;
    size_t index = --base->free.count;
    if (unlikely(index == 0)) free_pages = base->free.next;

    mutex_unlock(&pmm_lock);
    return base + index;
}

void free_page_now(page_t *page) {
    page->free.count = 1;

    mutex_lock(&pmm_lock);
    page->free.next = free_pages;
    free_pages = page;

    pmm_stats.free += 1;
    pmm_stats.avail += 1;
    mutex_unlock(&pmm_lock);
}
