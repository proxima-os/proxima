#include "mem/vmm.h"
#include "asm/fsgsbase.h"
#include "asm/msr.h"
#include "proxima/compiler.h"
#include "cpu/cpu.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "sched/proc.h"
#include "sys/syscall.h"

syscall_result_t sys_mmap(uintptr_t addr, size_t size, int flags, int fd, size_t offset) {
    if (fd >= 0) {
        file_t *file = get_file_description(current_proc, fd, false);
        if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

        int error = vfs_mmap(file, &addr, size, flags, offset, O_RDONLY);
        file_deref(file);
        if (unlikely(error)) return SYSCALL_ERR(error);
    } else {
        int error = vmm_add(&addr, size, flags, NULL, 0);
        if (unlikely(error)) return SYSCALL_ERR(error);
    }

    return SYSCALL_NUM(addr);
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
