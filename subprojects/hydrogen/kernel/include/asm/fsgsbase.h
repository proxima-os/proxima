#ifndef HYDROGEN_ASM_FSGSBASE_H
#define HYDROGEN_ASM_FSGSBASE_H

#include <stdint.h>

static inline uintptr_t rdfsbase(void) {
    uintptr_t value;
    asm volatile("rdfsbase %0" : "=r"(value));
    return value;
}

static inline void wrfsbase(uintptr_t value) {
    asm("wrfsbase %0" ::"r"(value));
}

#endif // HYDROGEN_ASM_FSGSBASE_H
