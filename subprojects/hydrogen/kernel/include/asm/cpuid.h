#ifndef HYRDOGEN_ASM_CPUID_H
#define HYRDOGEN_ASM_CPUID_H

#include <stdbool.h>
#include <stdint.h>

static inline void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    asm volatile("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "0"(leaf));
}

static inline void cpuid2(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    asm volatile("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "0"(leaf), "2"(subleaf));
}

static inline bool try_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    cpuid(leaf & 0x80000000, eax, ebx, ecx, edx);
    if (*eax < leaf) return false;
    cpuid(leaf, eax, ebx, ecx, edx);
    return true;
}

static inline bool try_cpuid2(
        uint32_t leaf,
        uint32_t subleaf,
        uint32_t *eax,
        uint32_t *ebx,
        uint32_t *ecx,
        uint32_t *edx
) {
    cpuid(leaf & 0x80000000, eax, ebx, ecx, edx);
    if (*eax < leaf) return false;
    cpuid2(leaf, subleaf, eax, ebx, ecx, edx);
    return true;
}

#endif // HYRDOGEN_ASM_CPUID_H
