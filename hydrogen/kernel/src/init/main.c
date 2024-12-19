#include "asm/idle.h"
#include "asm/irq.h"
#include "compiler.h"
#include "cpu/exc.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "cpu/lapic.h"
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

static void test_task(void *ctx) {
    uint64_t threshold = timeconv_apply(ns2tsc_conv, 1000000); // 1 millisecond

    uint64_t last = read_time();

    for (;;) {
        uint64_t cur = read_time();

        if (cur - last > threshold) {
            uint64_t last_ns = timeconv_apply(tsc2ns_conv, last);
            uint64_t cur_ns = timeconv_apply(tsc2ns_conv, cur);
            uint64_t diff_ns = cur_ns - last_ns;
            printk("Potential task switch onto %s(%d): last was at %U.%9U, now %U.%9U (diff %U.%9U)\n",
                   ctx,
                   current_task->priority,
                   last_ns / 1000000000,
                   last_ns % 1000000000,
                   cur_ns / 1000000000,
                   cur_ns % 1000000000,
                   diff_ns / 1000000000,
                   diff_ns % 1000000000);
        }

        last = cur;
    }
}

static void init_kernel(UNUSED void *ctx) {
    init_acpi_fully();

    task_t *t1, *t2;
    int error = sched_create(&t1, test_task, "Task 1");
    if (error) panic("1 (%d)", error);
    error = sched_create(&t2, test_task, "Task 2");
    if (error) panic("2 (%d)", error);
    sched_start(t1);
    sched_start(t2);
    task_deref(t1);
    task_deref(t2);

    // panic("TODO");
}

_Noreturn void kernel_main(void) {
    boot_tsc = read_time();
    init_gdt();
    init_idt();
    init_exc();

    init_print();
    printk("Starting Hydrogen...\n");

    if (!LIMINE_BASE_REVISION_SUPPORTED) panic("requested base revision not supported");

    init_pmm();
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
