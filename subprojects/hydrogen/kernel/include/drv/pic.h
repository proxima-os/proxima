#ifndef HYDROGEN_DRV_PIC_H
#define HYDROGEN_DRV_PIC_H

#include <stdint.h>

#define PIC_NMI (4u << 8)
#define PIC_ACTIVE_LOW (1u << 13)
#define PIC_LEVEL_TRIG (1u << 15)

void init_pic(void);

void pic_setup_isa(uint32_t irq, uint32_t vector);

void pic_setup_irq(uint32_t irq, uint32_t vector, uint32_t flags);

void pic_reset_isa(uint32_t irq);

void pic_reset_irq(uint32_t irq);

// Returns -1 if allocation failed. `align` must be a power of two.
int alloc_irq_vectors(uint32_t count, uint32_t align);

void free_irq_vectors(int base, uint32_t count);

void pic_install_vector(int vector, void (*handler)(void *), void *ctx);

void pic_uninstall_vector(int vector, void (*handler)(void *));

#endif // HYDROGEN_DRV_PIC_H
