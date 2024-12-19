#ifndef HYDROGEN_ASM_CR_H
#define HYDROGEN_ASM_CR_H

#include <stddef.h>
#include <stdint.h>

#define CR0_MP (1u << 1)
#define CR0_EM (1u << 2)
#define CR0_TS (1u << 3)
#define CR0_NE (1u << 5)
#define CR0_AM (1u << 18)

#define CR4_TSD (1u << 2)
#define CR4_DE (1u << 3)
#define CR4_PGE (1u << 7)
#define CR4_OSFXSR (1u << 9)
#define CR4_OSXMMEXCPT (1u << 10)
#define CR4_UMIP (1u << 11)
#define CR4_FSGSBASE (1u << 16)
#define CR4_OSXSAVE (1u << 18)
#define CR4_SMEP (1u << 20)
#define CR4_SMAP (1u << 21)

static inline size_t read_cr0(void) {
    size_t value;
    asm volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

static inline size_t read_cr2(void) {
    size_t value;
    asm volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

static inline size_t read_cr3(void) {
    size_t value;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline size_t read_cr4(void) {
    size_t value;
    asm volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

static inline size_t read_cr8(void) {
    size_t value;
    asm volatile("mov %%cr8, %0" : "=r"(value));
    return value;
}

static inline void write_cr0(size_t value) {
    asm("mov %0, %%cr0" ::"r"(value));
}

static inline void write_cr3(size_t value) {
    asm("mov %0, %%cr3" ::"r"(value));
}

static inline void write_cr4(size_t value) {
    asm("mov %0, %%cr4" ::"r"(value));
}

static inline void write_cr8(size_t value) {
    asm("mov %0, %%cr8" ::"r"(value));
}

static inline void write_xcr(uint32_t cr, uint64_t value) {
    uint32_t low = value;
    uint32_t high = value >> 32;
    asm("xsetbv" ::"a"(low), "d"(high), "c"(cr));
}

static inline uint64_t read_xcr(uint32_t cr) {
    uint32_t low;
    uint32_t high;
    asm volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(cr));
    return ((uint64_t)high << 32) | low;
}

#endif // HYDROGEN_ASM_CR_H
