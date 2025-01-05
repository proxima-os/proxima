#include "mem/vmm.h"
#include "asm/fsgsbase.h"
#include "asm/msr.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "sys/syscall.h"

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
