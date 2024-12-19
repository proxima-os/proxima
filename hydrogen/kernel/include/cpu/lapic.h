#ifndef HYDROGEN_CPU_LAPIC_H
#define HYDROGEN_CPU_LAPIC_H

#include <stdint.h>

typedef enum {
    TIMER_ONESHOT,
    TIMER_TSC_DEADLINE = 2u << 17,
} timer_mode_t;

extern uint32_t cpu_apic_id;
extern uint32_t cpu_acpi_id;

void init_lapic(void);

void lapic_eoi(void);

void lapic_timcal_start(void);

uint32_t lapic_timcal_read(void);

void lapic_setup_timer(timer_mode_t mode);

void lapic_arm_timer(uint32_t ticks);

#endif // HYDROGEN_CPU_LAPIC_H
