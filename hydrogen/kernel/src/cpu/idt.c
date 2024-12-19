#include "cpu/idt.h"
#include "asm/irq.h"
#include "asm/tables.h"
#include "compiler.h"
#include "cpu/gdt.h"
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

    lidt(idt, sizeof(idt));
}

void idt_install(uint8_t vector, idt_handler_t handler) {
    irq_state_t state = save_disable_irq();
    ASSERT(handlers[vector] == NULL);
    handlers[vector] = handler;
    restore_irq(state);
}

void idt_uninstall(uint8_t vector, UNUSED idt_handler_t handler) {
    irq_state_t state = save_disable_irq();
    ASSERT(handlers[vector] == handler);
    handlers[vector] = NULL;
    restore_irq(state);
}

void idt_dispatch(idt_frame_t *frame) {
    idt_handler_t handler = handlers[frame->vector];
    if (handler) handler(frame);
}
