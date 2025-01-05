#include "sys/syscall.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "hydrogen/error.h"
#include "hydrogen/stat.h"
#include "mem/pmap.h"
#include "mem/vheap.h"
#include "proxima/compiler.h"
#include "sched/proc.h"
#include "sys/sysvecs.h"
#include "sys/vdso.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

_Static_assert(GDT_SEL_KCODE + 8 == GDT_SEL_KDATA, "GDT kernel selectors are in wrong layout for syscall");
_Static_assert(GDT_SEL_UDATA + 8 == GDT_SEL_UCODE, "GDT user selectors are in wrong layout for syscall");

extern const void syscall_entry;

int (*memcpy_user)(void *, const void *, size_t);
int (*memset_user)(void *, int, size_t);

extern int normal_memcpy_user(void *, const void *, size_t);
extern int normal_memset_user(void *, int, size_t);
extern int smap_memcpy_user(void *, const void *, size_t);
extern int smap_memset_user(void *, int, size_t);

void syscall_init(void) {
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | MSR_EFER_SCE);
    wrmsr(MSR_STAR, ((uint64_t)(GDT_SEL_UDATA - 8) << 48) | ((uint64_t)GDT_SEL_KCODE << 32));
    wrmsr(MSR_LSTAR, (uint64_t)&syscall_entry);
    wrmsr(MSR_FMASK, 0x600); // Clear DF and IF on entry

    if (smap_supported) {
        memcpy_user = smap_memcpy_user;
        memset_user = smap_memset_user;
    } else {
        memcpy_user = normal_memcpy_user;
        memset_user = normal_memset_user;
    }
}

static syscall_result_t do_syscall(
        syscall_vector_t num,
        size_t a0,
        size_t a1,
        size_t a2,
        size_t a3,
        size_t a4,
        size_t a5
) {
    switch (num) {
    case SYS_EXIT: hydrogen_exit();
    case SYS_MMAP: return sys_mmap(a0, a1, a2, a3, a4);
    case SYS_MPROTECT: return sys_mprotect(a0, a1, a2);
    case SYS_MUNMAP: return sys_munmap(a0, a1);
    case SYS_GET_FS_BASE: return sys_get_fs_base();
    case SYS_GET_GS_BASE: return sys_get_gs_base();
    case SYS_SET_FS_BASE: return sys_set_fs_base(a0);
    case SYS_SET_GS_BASE: return sys_set_gs_base(a0);
    case SYS_UMASK: return sys_umask(a0);
    case SYS_OPEN: return sys_open(a0, (const void *)a1, a2, a3, a4);
    case SYS_REOPEN: return sys_reopen(a0, a1);
    case SYS_DUP: return sys_dup(a0, a1, a2, a3);
    case SYS_CLOSE: return sys_close(a0);
    case SYS_MKNOD: return sys_mknod(a0, (const void *)a1, a2, a3);
    case SYS_SYMLINK: return sys_symlink(a0, (const void *)a1, a2, (const void *)a3, a4);
    case SYS_LINK: return sys_link((const sys_link_args_t *)a0);
    case SYS_UNLINK: return sys_unlink(a0, (const void *)a1, a2, a3);
    case SYS_RENAME: return sys_rename(a0, (const void *)a1, a2, a3, (const void *)a4, a5);
    case SYS_READLINK: return sys_readlink(a0, (const void *)a1, a2, (void *)a3, a4);
    case SYS_STAT: return sys_stat(a0, (const void *)a1, a2, (hydrogen_stat_t *)a3, a4);
    case SYS_FSTAT: return sys_fstat(a0, (hydrogen_stat_t *)a1);
    case SYS_TRUNCATE: return sys_truncate(a0, (const void *)a1, a2, a3);
    case SYS_FTRUNCATE: return sys_ftruncate(a0, a1);
    case SYS_UTIMES: return sys_utimes(a0, (const void *)a1, a2, a3, a4, a5);
    case SYS_FUTIMES: return sys_futimes(a0, a1, a2);
    case SYS_CHOWN: return sys_chown(a0, (const void *)a1, a2, a3, a4, a5);
    case SYS_FCHOWN: return sys_fchown(a0, a1, a2);
    case SYS_CHMOD: return sys_chmod(a0, (const void *)a1, a2, a3, a4);
    case SYS_FCHMOD: return sys_fchmod(a0, a1);
    case SYS_SEEK: return sys_seek(a0, a1, a2);
    case SYS_READ: return sys_read(a0, (void *)a1, a2);
    case SYS_WRITE: return sys_write(a0, (const void *)a1, a2);
    case SYS_PREAD: return sys_pread(a0, (void *)a1, a2, a3);
    case SYS_PWRITE: return sys_pwrite(a0, (const void *)a1, a2, a3);
    case SYS_EXECVE: return sys_execve(a0, (const void *)a1, a2, (const sys_execve_args_t *)a3);
    case SYS_FEXECVE: return sys_fexecve(a0, (const sys_execve_args_t *)a1);
    default: return SYSCALL_ERR(ERR_NOT_IMPLEMENTED); break;
    }
}

void syscall_dispatch(idt_frame_t *frame) {
    if (!is_address_in_vdso(frame->rip)) {
        // TODO: Make this send a signal instead of panicking
        panic("syscalls are not allowed from outside vdso");
    }

    enable_irq();
    syscall_result_t
            result = do_syscall(frame->rax, frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
    disable_irq();

    frame->rax = result.value.num;
    frame->rdx = result.error;
}

int verify_user_ptr(const void *ptr, size_t len) {
    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end = start + len;
    if (unlikely(end < start || end >= MAX_USER_VIRT_ADDR)) return ERR_INVALID_POINTER;
    return 0;
}

int verify_addr(uintptr_t addr) {
    if (unlikely(addr >= MAX_USER_VIRT_ADDR && addr < MIN_KERNEL_VIRT_ADDR)) return ERR_INVALID_ARGUMENT;
    return 0;
}

int copy_to_heap(void **buffer, const void *src, size_t size) {
    int error = verify_user_ptr(src, size);
    if (unlikely(error)) return error;

    void *buf = vmalloc(size);
    if (unlikely(!buffer)) return ERR_OUT_OF_MEMORY;

    error = memcpy_user(buf, src, size);
    if (unlikely(error)) {
        vmfree(buf, size);
        return error;
    }

    *buffer = buf;
    return 0;
}

int fd_to_file_opt(int fd, file_t **out) {
    if (fd < 0) {
        *out = NULL;
        return 0;
    }

    file_t *file = get_file_description(current_proc, fd, false);
    *out = file;
    return likely(file) ? 0 : ERR_INVALID_HANDLE;
}
