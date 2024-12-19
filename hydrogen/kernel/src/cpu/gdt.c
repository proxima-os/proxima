#include "cpu/gdt.h"
#include "asm/tables.h"
#include "cpu/tss.h"
#include <stdint.h>

static gdt_t gdt = {
        .kernel_code = 0x209b0000000000,
        .kernel_data = 0x40930000000000,
};

extern void switch_segments(uint64_t code, uint64_t data);

void init_gdt(void) {
    uintptr_t tss = (uintptr_t)&kernel_tss;
    gdt.tss_low = (sizeof(kernel_tss) - 1) | ((tss & 0xffffff) << 16) | (0x89ul << 40) | ((tss & 0xff000000) << 32);
    gdt.tss_high = tss >> 32;

    lgdt(&gdt, sizeof(gdt));
    lldt(0);
    switch_segments(GDT_SEL_KCODE, GDT_SEL_KDATA);
    ltr(GDT_SEL_TSS);
}
