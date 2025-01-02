#ifndef HYDROGEN_CPU_CPU_H
#define HYDROGEN_CPU_CPU_H

#include "cpu/gdt.h"
#include "cpu/tss.h"
#include "sched/sched.h"
#include "util/list.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

extern bool pg_supported;
extern bool nx_supported;
extern bool gb_pages_supported;
extern bool tsc_supported;
extern bool tsc_deadline_supported;
extern bool running_in_hypervisor;
extern bool tsc_invariant;
extern bool xsave_supported;
extern bool fsgsbase_supported;
extern bool smap_supported;
extern uint64_t cpu_paddr_mask;

typedef struct cpu {
    struct cpu *self;
    uintptr_t syscall_temp;
    uintptr_t kernel_stack;
    size_t id;
    cpu_gdt_t gdt;
    cpu_tss_t tss;
    uint32_t apic_id;
    bool apic_avail;
    uint32_t acpi_id;
    sched_t sched;

    timer_event_t *events;
    spinlock_t events_lock;

    struct cpu *next;

    struct pmap *pmap;
    list_node_t pmap_node;
} cpu_t;

typedef struct {
    cpu_t cpu;
    tss_init_data_t tss;
} cpu_init_data_t;

#define current_cpu (*(__seg_gs cpu_t *)0)
#define current_cpu_ptr (current_cpu.self)
#define current_task (*(task_t * __seg_gs *)offsetof(cpu_t, sched.current))

extern cpu_init_data_t bsp_init_data;
extern size_t num_cpus;

#define boot_cpu (&bsp_init_data.cpu)

void detect_cpu(void);

void init_cpu(cpu_init_data_t *data);

#endif // HYDROGEN_CPU_CPU_H
