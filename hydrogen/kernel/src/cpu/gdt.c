#include "cpu/gdt.h"
#include "asm/msr.h"
#include "asm/tables.h"
#include "cpu/cpu.h"
#include <stdint.h>

extern void switch_segments(uint64_t code, uint64_t data);

void init_gdt(cpu_t *cpu) {
    cpu_gdt_t *gdt = &cpu->gdt;

    uintptr_t tss = (uintptr_t)&cpu->tss;
    gdt->kernel_code = 0x209b0000000000;
    gdt->kernel_data = 0x40930000000000;
    gdt->user_code = 0x20fb0000000000;
    gdt->user_data = 0x40f30000000000;
    gdt->tss_low = (sizeof(cpu->tss) - 1) | ((tss & 0xffffff) << 16) | (0x89ul << 40) | ((tss & 0xff000000) << 32);
    gdt->tss_high = tss >> 32;

    lgdt(gdt, sizeof(*gdt));
    lldt(0);
    switch_segments(GDT_SEL_KCODE, GDT_SEL_KDATA);
    ltr(GDT_SEL_TSS);
    wrmsr(MSR_GS_BASE, (uintptr_t)cpu);
}
