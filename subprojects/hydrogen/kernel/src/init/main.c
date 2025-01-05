#include "asm/idle.h"
#include "asm/irq.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/idt.h"
#include "cpu/lapic.h"
#include "cpu/xsave.h"
#include "drv/acpi.h"
#include "drv/hpet.h"
#include "drv/pci.h"
#include "drv/pic.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "init/initrd.h"
#include "limine.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "sched/proc.h"
#include "sched/sched.h"
#include "string.h"
#include "sys/elf.h"
#include "sys/vdso.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/time.h"
#include <stddef.h>
#include <stdint.h>

__attribute__((used, section(".requests0"))) LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

extern const elf_header_t __vdso_start;

static void init_process_func(UNUSED void *ctx) {
    pmm_stats_t stats = get_pmm_stats();
    printk("mem: %uK total, %uK available, %uK free\n",
           stats.total << (PAGE_SHIFT - 10),
           stats.avail << (PAGE_SHIFT - 10),
           stats.free << (PAGE_SHIFT - 10));

    int error = map_vdso(&current_proc->vdso);
    if (error) panic("failed to map vdso (%d)", error);

    printk("mapped vdso at 0x%X\n", current_proc->vdso);

    uintptr_t stack_base = 0;
    error = vmm_add(&stack_base, PAGE_SIZE, VMM_READ | VMM_WRITE, NULL, 0);
    if (error) panic("failed to allocate user stack (%d)", error);

    file_t *kcon;
    error = create_kcon_handle(&kcon);
    if (error) panic("failed to allocate kernel console handle (%d)", error);

    int fd = alloc_fd(kcon, 0);
    if (fd < 0) panic("failed to allocate kernel console fd (%d)", -fd);
    file_deref(kcon);

    ASSERT(fd == 0);

    enter_user_mode(current_proc->vdso + __vdso_start.entry, stack_base + PAGE_SIZE - 8);
}

static void init_kernel(UNUSED void *ctx) {
    vfs_t *rootfs;
    ident_t *ident = get_identity();
    int error = ramfs_create(&rootfs, 0755, ident);
    ident_deref(ident);
    if (unlikely(error)) panic("failed to create root filesystem (%d)", error);
    set_root(rootfs->root);
    vnode_deref(rootfs->root);

    extract_initrds(NULL, "/", 1);
    reclaim_loader_memory();

    init_pci_access();
    init_acpi_fully();

    vmm_t *vmm;
    error = vmm_create(&vmm);
    if (error) panic("failed to create init vmm (%d)", error);

    proc_t *proc;
    error = create_process(&proc, init_process_func, NULL, vmm);
    if (error) panic("failed to create init process (%d)", error);
    proc_deref(proc);
    vmm_deref(vmm);
}

_Noreturn void kernel_main(void) {
    boot_tsc = read_time();

    detect_cpu();
    init_idt();
    init_exc();
    init_cpu(&bsp_init_data);
    init_sched_cpu();

    init_print();
    printk("Starting Hydrogen...\n");

    if (!LIMINE_BASE_REVISION_SUPPORTED) panic("requested base revision not supported");

    init_pmm();
    init_vdso();
    init_xsave_bsp();
    init_acpi_tables();
    init_lapic();
    init_pic();
    enable_irq();
    init_hpet();
    init_time();
    init_smp();
    init_proc();
    init_sched();

    task_t *init_task;
    int error = create_thread(&init_task, init_kernel, NULL, NULL);
    if (error) panic("failed to create init task (%d)", error);
    task_deref(init_task);

    for (;;) cpu_idle();
}
