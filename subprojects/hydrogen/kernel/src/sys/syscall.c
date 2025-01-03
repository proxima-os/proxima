#include "sys/syscall.h"
#include "asm/fsgsbase.h"
#include "asm/msr.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "hydrogen/error.h"
#include "mem/pmap.h"
#include "mem/vmm.h"
#include "sched/sched.h"
#include "sys/sysvecs.h"
#include "util/print.h"
#include <stdint.h>

_Static_assert(GDT_SEL_KCODE + 8 == GDT_SEL_KDATA, "GDT kernel selectors are in wrong layout for syscall");
_Static_assert(GDT_SEL_UDATA + 8 == GDT_SEL_UCODE, "GDT user selectors are in wrong layout for syscall");

extern const void syscall_entry;

void syscall_init(void) {
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | MSR_EFER_SCE);
    wrmsr(MSR_STAR, ((uint64_t)(GDT_SEL_UDATA - 8) << 48) | ((uint64_t)GDT_SEL_KCODE << 32));
    wrmsr(MSR_LSTAR, (uint64_t)&syscall_entry);
    wrmsr(MSR_FMASK, 0x600); // Clear DF and IF on entry
}

static syscall_result_t do_syscall(uintptr_t num, size_t a0, size_t a1, size_t a2) {
    switch (num) {
    case SYS_EXIT: sys_exit();
    case SYS_MMAP: return sys_mmap(a0, a1, a2);
    case SYS_MPROTECT: return sys_mprotect(a0, a1, a2);
    case SYS_MUNMAP: return sys_munmap(a0, a1);
    case SYS_GET_FS_BASE: return SYSCALL_NUM(fsgsbase_supported ? rdfsbase() : current_task->fs_base);
    case SYS_GET_GS_BASE: return SYSCALL_NUM(fsgsbase_supported ? rdmsr(MSR_KERNEL_GS_BASE) : current_task->gs_base);
    case SYS_SET_FS_BASE:
        if (fsgsbase_supported) wrfsbase(a0);
        else case SYS_PRINT:
            return sys_print((const void *)a0, a1);
    default: return SYSCALL_ERR(ERR_NOT_IMPLEMENTED); break;
    }
}

void syscall_dispatch(idt_frame_t *frame) {
    // syscall arguments are in rdi, rsi, rdx, r10, r8, r9
    syscall_result_t result = do_syscall(frame->rax, frame->rdi, frame->rsi, frame->rdx);

    frame->rax = result.value.num;
    frame->rdx = result.error;
}

int verify_user_ptr(const void *ptr, size_t len) {
    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end = start + len;
    if (unlikely(end < start || end >= MAX_USER_VIRT_ADDR)) return ERR_INVALID_ARGUMENT;
    return 0;
}

static int verify_addr(uintptr_t addr) {
    if (unlikely(addr >= MAX_USER_VIRT_ADDR && addr < MIN_KERNEL_VIRT_ADDR)) return ERR_INVALID_ARGUMENT;
    return 0;
}

_Noreturn void sys_exit(void) {
    sched_exit();
}

syscall_result_t sys_mmap(uintptr_t addr, size_t size, int flags) {
    int error = vmm_add(&addr, size, flags, NULL, 0);
    if (likely(error == 0)) return SYSCALL_NUM(addr);
    else return SYSCALL_ERR(error);
}

syscall_result_t sys_mprotect(uintptr_t addr, size_t size, int flags) {
    return SYSCALL_ERR(vmm_alter(addr, size, flags));
}

syscall_result_t sys_munmap(uintptr_t addr, size_t size) {
    return SYSCALL_ERR(vmm_del(addr, size));
}

syscall_result_t sys_get_fs_base(void) {
    return SYSCALL_NUM(fsgsbase_supported ? rdfsbase() : current_task->fs_base);
}

syscall_result_t sys_get_gs_base(void) {
    return SYSCALL_NUM(fsgsbase_supported ? rdmsr(MSR_KERNEL_GS_BASE) : current_task->gs_base);
}

syscall_result_t sys_set_fs_base(uintptr_t base) {
    int error = verify_addr(base);
    if (unlikely(error)) return SYSCALL_ERR(error);

    wrmsr(MSR_FS_BASE, base);
    current_task->fs_base = base;

    return SYSCALL_ERR(0);
}

syscall_result_t sys_set_gs_base(uintptr_t base) {
    int error = verify_addr(base);
    if (unlikely(error)) return SYSCALL_ERR(error);

    wrmsr(MSR_KERNEL_GS_BASE, base);
    current_task->gs_base = base;

    return SYSCALL_ERR(0);
}

syscall_result_t sys_print(const void *buf, size_t len) {
    int error = verify_user_ptr(buf, len);
    if (error) return SYSCALL_ERR(error);

    printk("%S", buf, len);
    return SYSCALL_ERR(0);
}
