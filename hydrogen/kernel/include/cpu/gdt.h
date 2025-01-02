#ifndef HYDROGEN_CPU_GDT_H
#define HYDROGEN_CPU_GDT_H

#include <stddef.h>
#include <stdint.h>

typedef struct cpu cpu_t;

typedef struct {
    uint64_t reserved;
    uint64_t kernel_code;
    uint64_t kernel_data;
    uint64_t user_data;
    uint64_t user_code;
    uint64_t tss_low;
    uint64_t tss_high;
} __attribute__((aligned(8), packed)) cpu_gdt_t;

#define GDT_SEL_KCODE offsetof(cpu_gdt_t, kernel_code)
#define GDT_SEL_KDATA offsetof(cpu_gdt_t, kernel_data)
#define GDT_SEL_UCODE offsetof(cpu_gdt_t, user_code)
#define GDT_SEL_UDATA offsetof(cpu_gdt_t, user_data)
#define GDT_SEL_TSS offsetof(cpu_gdt_t, tss_low)

void init_gdt(cpu_t *cpu);

#endif // HYDROGEN_CPU_GDT_H
