#ifndef HYDROGEN_ASM_CR_H
#define HYDROGEN_ASM_CR_H

#include <stddef.h>

#define CR4_PGE 0x80

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

static inline void write_cr3(size_t value) {
    asm("mov %0, %%cr3" ::"r"(value));
}

static inline void write_cr4(size_t value) {
    asm("mov %0, %%cr4" ::"r"(value));
}

#endif // HYDROGEN_ASM_CR_H
