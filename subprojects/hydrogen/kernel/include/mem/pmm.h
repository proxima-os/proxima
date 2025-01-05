#ifndef HYDROGEN_MEM_PMM_H
#define HYDROGEN_MEM_PMM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ul << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)

typedef union page {
    struct {
        union page *next;
        size_t count;
    } free;
    struct {
        union page *prev;
        union page *next;
        struct free_obj *objs;
        size_t free;
    } heap;
    struct {
        size_t references;
        union page *shootdown_next;
        bool autounreserve;
    } anon;
} page_t;

typedef struct {
    size_t total;
    size_t avail;
    size_t free;
} pmm_stats_t;

extern void *hhdm_start;
extern page_t *page_array;

void init_pmm(void);

void reclaim_loader_memory(void);

pmm_stats_t get_pmm_stats(void);

uint64_t sym_to_phys(const void *sym);

bool reserve_pages(size_t count);

// all pages in this reservation must have been freed
void unreserve_pages(size_t count);

// you must have a reservation for at least one page, always succeeds
page_t *alloc_page(void);

// you must have a reservation for at least one page
void free_page(page_t *page);

// does not require a reservation, returns null on error
page_t *alloc_page_now(void);

// also unreserves the page
void free_page_now(page_t *page);

static inline uint64_t page_to_phys(page_t *page) {
    return (page - page_array) << PAGE_SHIFT;
}

static inline void *page_to_virt(page_t *page) {
    return hhdm_start + ((page - page_array) << PAGE_SHIFT);
}

static inline page_t *phys_to_page(uint64_t phys) {
    return page_array + (phys >> PAGE_SHIFT);
}

static inline void *phys_to_virt(uint64_t phys) {
    return hhdm_start + phys;
}

static inline page_t *virt_to_page(const void *virt) {
    return page_array + ((virt - hhdm_start) >> PAGE_SHIFT);
}

static inline uint64_t virt_to_phys(const void *virt) {
    return virt - hhdm_start;
}

#endif // HYDROGEN_MEM_PMM_H
