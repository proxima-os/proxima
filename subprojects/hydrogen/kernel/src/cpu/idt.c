#include "cpu/idt.h"
#include "asm/msr.h"
#include "asm/tables.h"
#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "proxima/compiler.h"
#include "util/panic.h"
#include <stdint.h>

typedef struct {
    uint16_t offset0;
    uint16_t selector;
    uint8_t ist;
    uint8_t flags;
    uint16_t offset1;
    uint64_t offset2;
} __attribute__((aligned(16), packed)) idt_entry_t;

static idt_entry_t idt[256];
static idt_handler_t handlers[256];
extern uintptr_t idt_stubs[256];

void init_idt(void) {
    for (int i = 0; i < 256; i++) {
        uintptr_t stub = idt_stubs[i];
        if (stub == 0) continue;

        idt[i].offset0 = stub;
        idt[i].selector = GDT_SEL_KCODE;
        idt[i].flags = 0x8e;
        idt[i].offset1 = stub >> 16;
        idt[i].offset2 = stub >> 32;
    }

    idt[2].ist = 1;
    idt[8].ist = 1;
    idt[18].ist = 1;
}

void load_idt(void) {
    lidt(idt, sizeof(idt));
}

void idt_install(uint8_t vector, idt_handler_t handler) {
    UNUSED idt_handler_t old = __atomic_exchange_n(&handlers[vector], handler, __ATOMIC_ACQ_REL);
    ASSERT(old == NULL);
}

void idt_uninstall(uint8_t vector, UNUSED idt_handler_t handler) {
    UNUSED idt_handler_t old = __atomic_exchange_n(&handlers[vector], NULL, __ATOMIC_ACQ_REL);
    ASSERT(old == handler);
}

bool paranoid_enter(idt_frame_t *frame) {
    uint64_t wanted_base = *(uint64_t *)&frame[1];
    uint64_t current_base = rdmsr(MSR_GS_BASE);
    bool should_swap = wanted_base != current_base;
    if (should_swap) asm("swapgs");
    return should_swap;
}

void paranoid_exit(bool swapped) {
    if (swapped) asm("swapgs");
}

void idt_dispatch(idt_frame_t *frame) {
    if (smap_supported) asm("clac");

    idt_handler_t handler = handlers[frame->vector];
    if (handler) handler(frame);
}
