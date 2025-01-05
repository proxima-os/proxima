#include "asm/idle.h"
#include "asm/irq.h"
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
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "init/initrd.h"
#include "limine.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "proxima/compiler.h"
#include "sched/exec.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "sched/sched.h"
#include "string.h"
#include "sys/vdso.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/time.h"
#include <stddef.h>
#include <stdint.h>

__attribute__((used, section(".requests0"))) LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

static const char *init_names[] = {
        "/bin/init",
        "/bin/sh",
};

static void init_process_func(UNUSED void *ctx) {
    pmm_stats_t stats = get_pmm_stats();
    printk("mem: %uK total, %uK available, %uK free\n",
           stats.total << (PAGE_SHIFT - 10),
           stats.avail << (PAGE_SHIFT - 10),
           stats.free << (PAGE_SHIFT - 10));

    file_t *kcon;
    int error = create_kcon_handle(&kcon);
    if (error) panic("failed to allocate kernel console handle (%d)", error);

    mutex_lock(&current_proc->fds_lock);

    for (int i = 0; i < 3; i++) {
        int error = assign_fd(current_proc, i, kcon, 0);
        if (error) panic("failed to assign fd to kernel console (%d)", error);
    }

    mutex_unlock(&current_proc->fds_lock);
    file_deref(kcon);

    execve_string_t *str = vmalloc(sizeof(*str));
    if (!str) panic("failed to allocate execve args");

    for (size_t i = 0; i < sizeof(init_names) / sizeof(*init_names); i++) {
        printk("executing init at %s...\n", init_names[i]);

        size_t len = strlen(init_names[i]);

        file_t *file;
        error = vfs_open(NULL, &file, init_names[i], len, O_EXEC | O_NODIR, 0);

        if (likely(error == 0)) {
            str->data = vmalloc(len);
            if (!str->data) panic("failed to allocate execve argument string");
            memcpy(str->data, init_names[i], len);
            str->length = len;

            error = execve(file, str, 1, NULL, 0);
            panic("execve failed (%d)", error);
        } else if (error == ERR_NOT_FOUND) {
            printk("failed to open executable (%d)\n", error);
        } else {
            panic("failed to open init executable (%d)", error);
        }
    }

    panic("failed to start init process");
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
