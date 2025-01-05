#include "proxima/compiler.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "sched/proc.h"
#include "sys/syscall.h"

syscall_result_t sys_seek(int fd, uint64_t offset, hydrogen_whence_t whence) {
    if (unlikely(whence != HYDROGEN_WHENCE_SET && whence != HYDROGEN_WHENCE_CUR && whence != HYDROGEN_WHENCE_END)) {
        return SYSCALL_ERR(ERR_INVALID_ARGUMENT);
    }

    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    int error = vfs_seek(file, &offset, whence);
    file_deref(file);

    return likely(!error) ? SYSCALL_NUM(offset) : SYSCALL_ERR(error);
}

syscall_result_t sys_read(int fd, void *buf, size_t size) {
    int error = verify_user_ptr(buf, size);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    error = vfs_read(file, buf, &size, O_RDONLY);
    file_deref(file);

    return likely(!error) ? SYSCALL_NUM(size) : SYSCALL_ERR(error);
}

syscall_result_t sys_write(int fd, const void *buf, size_t size) {
    int error = verify_user_ptr(buf, size);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    error = vfs_write(file, buf, &size);
    file_deref(file);

    return likely(!error) ? SYSCALL_NUM(size) : SYSCALL_ERR(error);
}

syscall_result_t sys_pread(int fd, void *buf, size_t size, uint64_t position) {
    int error = verify_user_ptr(buf, size);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    error = vfs_pread(file, buf, &size, position, O_RDONLY);
    file_deref(file);

    return likely(!error) ? SYSCALL_NUM(size) : SYSCALL_ERR(error);
}

syscall_result_t sys_pwrite(int fd, const void *buf, size_t size, uint64_t position) {
    int error = verify_user_ptr(buf, size);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    error = vfs_pwrite(file, buf, &size, position);
    file_deref(file);

    return likely(!error) ? SYSCALL_NUM(size) : SYSCALL_ERR(error);
}
