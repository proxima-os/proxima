#ifndef HYDROGEN_SYS_SYSCALL_H
#define HYDROGEN_SYS_SYSCALL_H

#include "sys/sysvecs.h"
#include <stdint.h>

#define SYSCALL_NUM(val) ((syscall_result_t){.value.num = (val)})
#define SYSCALL_PTR(val) ((syscall_result_t){.value.ptr = (val)})
#define SYSCALL_ERR(err) ((syscall_result_t){.error = (err)})

void syscall_init(void);

int verify_user_ptr(const void *ptr, size_t len);

_Noreturn void sys_exit(void);

syscall_result_t sys_mmap(uintptr_t addr, size_t size, int flags);

syscall_result_t sys_mprotect(uintptr_t addr, size_t size, int flags);

syscall_result_t sys_munmap(uintptr_t addr, size_t size);

syscall_result_t sys_print(const void *buf, size_t len);

#endif // HYDROGEN_SYS_SYSCALL_H
