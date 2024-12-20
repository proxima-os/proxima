#ifndef HYDROGEN_ASM_MSR_H
#define HYDROGEN_ASM_MSR_H

#include <stdint.h>

#define MSR_TSC_DEADLINE 0x6e0

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value;
    uint32_t high = value >> 32;

    asm("wrmsr" ::"a"(low), "d"(high), "c"(msr));
}

#endif // HYDROGEN_ASM_MSR_H
