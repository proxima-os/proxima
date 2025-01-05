#include "hydrogen/vfs.h"
#include "proxima/compiler.h"
#include "sys/sysvecs.h"
#include "syscall.h"

int hydrogen_seek(int fd, uint64_t *offset, hydrogen_whence_t whence) {
    syscall_result_t result = syscall3(SYS_SEEK, fd, *offset, whence);
    if (unlikely(result.error)) return result.error;

    *offset = result.value.num;
    return 0;
}

hydrogen_io_res_t hydrogen_read(int fd, void *buffer, size_t size) {
    syscall_result_t result = syscall3(SYS_READ, fd, (uintptr_t)buffer, size);
    return (hydrogen_io_res_t){result.value.num, result.error};
}

hydrogen_io_res_t hydrogen_write(int fd, const void *buffer, size_t size) {
    syscall_result_t result = syscall3(SYS_WRITE, fd, (uintptr_t)buffer, size);
    return (hydrogen_io_res_t){result.value.num, result.error};
}

hydrogen_io_res_t hydrogen_pread(int fd, void *buffer, size_t size, uint64_t position) {
    syscall_result_t result = syscall4(SYS_PREAD, fd, (uintptr_t)buffer, size, position);
    return (hydrogen_io_res_t){result.value.num, result.error};
}

hydrogen_io_res_t hydrogen_pwrite(int fd, const void *buffer, size_t size, uint64_t position) {
    syscall_result_t result = syscall4(SYS_PWRITE, fd, (uintptr_t)buffer, size, position);
    return (hydrogen_io_res_t){result.value.num, result.error};
}
