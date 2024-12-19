#include "mem/pmm.h"
#include "limine.h"
#include "mem/pmap.h"
#include "sched/mutex.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

// TODO: Make the init code work for PAGE_SHIFT != 12

void *hhdm_start;
page_t *page_array;

static uint64_t kernel_phys;
static struct limine_memmap_response *mmap;

static page_t *free_pages;
static size_t avail_pages;
static mutex_t pmm_lock;

extern const void _start;
extern const void _erodata;
extern const void _etext;
extern const void _end;

static void free_regions(uint64_t type) {
    for (uint64_t i = 0; i < mmap->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap->entries[i];
        if (entry->length == 0) continue;

        if (entry->type == type) {
            page_t *page = phys_to_page(entry->base);
            page->free.next = free_pages;
            page->free.count = entry->length >> PAGE_SHIFT;
            free_pages = page;

            avail_pages += page->free.count;
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

    uint64_t max_phys_addr = 0;

    for (uint64_t i = mmap->entry_count; i > 0; i--) {
        struct limine_memmap_entry *entry = mmap->entries[i - 1];
        if (entry->length == 0) continue;

        if (entry->type == LIMINE_MEMMAP_USABLE || entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) {
            max_phys_addr = entry->base + entry->length;
            break;
        }
    }

    if (max_phys_addr == 0) panic("no usable regions in memory map");

    size_t page_array_size = ((max_phys_addr >> PAGE_SHIFT) * sizeof(page_t) + PAGE_MASK) & ~PAGE_MASK;

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

    uint64_t map_start = 0;
    uint64_t map_end = 0;

    for (uint64_t i = 0; i < mmap->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap->entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) continue;
        if (entry->length == 0) continue;

        if (map_end != entry->base) {
            extend_hhdm(map_start, map_end - map_start, CACHE_WRITEBACK);
            map_start = map_end = entry->base;
        }

        map_end += entry->length;
    }

    extend_hhdm(map_start, map_end - map_start, CACHE_WRITEBACK);

    extend_hhdm(virt_to_phys(page_array), page_array_size, CACHE_WRITEBACK);
    map_print();

    map_segment(&_start, &_erodata, 0);
    map_segment(&_erodata, &_etext, PMAP_EXEC);
    map_segment(&_etext, &_end, PMAP_WRITE);

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

uint64_t sym_to_phys(const void *sym) {
    return kernel_phys + (sym - &_start);
}

bool reserve_pages(size_t count) {
    mutex_lock(&pmm_lock);
    bool success = count <= avail_pages;
    if (success) avail_pages -= count;
    mutex_unlock(&pmm_lock);
    return success;
}

void unreserve_pages(size_t count) {
    mutex_lock(&pmm_lock);
    avail_pages += count;
    mutex_unlock(&pmm_lock);
}

page_t *alloc_page(void) {
    mutex_lock(&pmm_lock);
    page_t *base = free_pages;
    size_t index = --base->free.count;
    if (index == 0) free_pages = base->free.next;
    mutex_unlock(&pmm_lock);
    return base + index;
}

void free_page(page_t *page) {
    page->free.count = 1;

    mutex_lock(&pmm_lock);
    page->free.next = free_pages;
    free_pages = page;
    mutex_unlock(&pmm_lock);
}

page_t *alloc_page_now(void) {
    mutex_lock(&pmm_lock);

    if (avail_pages == 0) {
        mutex_unlock(&pmm_lock);
        return NULL;
    }

    avail_pages -= 1;

    page_t *base = free_pages;
    size_t index = --base->free.count;
    if (index == 0) free_pages = base->free.next;

    mutex_unlock(&pmm_lock);
    return base + index;
}

void free_page_now(page_t *page) {
    page->free.count = 1;

    mutex_lock(&pmm_lock);
    page->free.next = free_pages;
    free_pages = page;

    avail_pages += 1;
    mutex_unlock(&pmm_lock);
}
