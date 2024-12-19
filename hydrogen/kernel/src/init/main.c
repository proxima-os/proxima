#include "asm/idle.h"
#include "asm/irq.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "cpu/lapic.h"
#include "cpu/xsave.h"
#include "drv/acpi.h"
#include "drv/hpet.h"
#include "drv/pic.h"
#include "limine.h"
#include "mem/pmm.h"
#include "sched/sched.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/time.h"
#include <stdint.h>

__attribute__((used, section(".requests0"))) LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

static void init_kernel(UNUSED void *ctx) {
    init_acpi_fully();

    panic("TODO");
}

_Noreturn void kernel_main(void) {
    boot_tsc = read_time();
    init_cpu();

    init_print();
    printk("Starting Hydrogen...\n");

    if (!LIMINE_BASE_REVISION_SUPPORTED) panic("requested base revision not supported");

    init_pmm();
    init_xsave();
    init_acpi_tables();
    init_lapic();
    reclaim_loader_memory();
    init_pic();
    enable_irq();
    init_hpet();
    init_time();
    init_sched();

    task_t *init_task;
    int error = sched_create(&init_task, init_kernel, NULL);
    if (error) panic("failed to create init task (%d)", error);
    sched_start(init_task);
    task_deref(init_task);

    for (;;) cpu_idle();
}
