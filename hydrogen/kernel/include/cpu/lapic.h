#ifndef HYDROGEN_CPU_LAPIC_H
#define HYDROGEN_CPU_LAPIC_H

#include "cpu/cpu.h"
#include <stdint.h>

typedef enum {
    TIMER_ONESHOT,
    TIMER_TSC_DEADLINE = 2u << 17,
} timer_mode_t;

void init_lapic(void);

void init_smp(void);

void lapic_eoi(void);

void lapic_timcal_start(void);

uint32_t lapic_timcal_read(void);

void lapic_setup_timer(timer_mode_t mode);

void lapic_arm_timer(uint32_t ticks);

void lapic_send_ipi(cpu_t *cpu, uint8_t vector);

#endif // HYDROGEN_CPU_LAPIC_H
