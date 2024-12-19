#ifndef HYDROGEN_CPU_GDT_H
#define HYDROGEN_CPU_GDT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t reserved;
    uint64_t kernel_code;
    uint64_t kernel_data;
    uint64_t tss_low;
    uint64_t tss_high;
} __attribute__((aligned(8), packed)) gdt_t;

#define GDT_SEL_KCODE offsetof(gdt_t, kernel_code)
#define GDT_SEL_KDATA offsetof(gdt_t, kernel_data)
#define GDT_SEL_TSS offsetof(gdt_t, tss_low)

void init_gdt(void);

#endif // HYDROGEN_CPU_GDT_H
