#ifndef HYDROGEN_ASM_IRQ_H
#define HYDROGEN_ASM_IRQ_H

typedef unsigned long irq_state_t;

static inline void disable_irq(void) {
    asm("cli");
}

static inline void enable_irq(void) {
    asm("sti");
}

static inline irq_state_t save_disable_irq(void) {
    irq_state_t state;
    asm volatile("pushfq \n\t"
                 "popq %0"
                 : "=rm"(state));
    if (state & 0x200) disable_irq();
    return state;
}

static inline void restore_irq(irq_state_t state) {
    if (state & 0x200) enable_irq();
}

#endif // HYDROGEN_ASM_IRQ_H
