#include "proxima/compiler.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "mem/vheap.h"
#include "sched/proc.h"
#include "sys/syscall.h"
#include "util/panic.h"

syscall_result_t sys_open(int fd, const void *path, size_t path_len, int flags, uint32_t mode) {
    int error = verify_user_ptr(path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *kpath;
    error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *file;

    if (fd >= 0) {
        file = get_file_description(current_proc, fd, false);
        if (unlikely(!file)) {
            vmfree(kpath, path_len);
            return SYSCALL_ERR(ERR_INVALID_HANDLE);
        }
    } else {
        file = NULL;
    }

    file_t *description;
    error = vfs_open(file, &description, kpath, path_len, flags, mode);
    if (file) file_deref(file);
    vmfree(kpath, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    int fdflags = 0;
    if (flags & O_CLOEXEC) fdflags |= FD_CLOEXEC;
    if (flags & O_CLOFORK) fdflags |= FD_CLOFORK;

    error = alloc_fd(description, fdflags);
    file_deref(description);

    return likely(error >= 0) ? SYSCALL_NUM(error) : SYSCALL_ERR(-error);
}

syscall_result_t sys_reopen(int fd, int flags) {
    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    file_t *description;
    int error = vfs_reopen(file, &description, flags);
    file_deref(file);
    if (unlikely(error)) return SYSCALL_ERR(error);

    int fdflags = 0;
    if (flags & O_CLOEXEC) fdflags |= FD_CLOEXEC;
    if (flags & O_CLOFORK) fdflags |= FD_CLOFORK;

    error = alloc_fd(description, fdflags);
    file_deref(description);

    return likely(error >= 0) ? SYSCALL_NUM(error) : SYSCALL_ERR(-error);
}

#define FD_FLAGS (FD_CLOFORK | FD_CLOEXEC)

syscall_result_t sys_dup(int fd, int min, int flags, bool exact) {
    if (fd < 0) return SYSCALL_ERR(ERR_INVALID_HANDLE);
    if (min < 0) return SYSCALL_ERR(ERR_INVALID_ARGUMENT);
    if (flags & ~FD_FLAGS) return SYSCALL_ERR(ERR_INVALID_ARGUMENT);

    mutex_lock(&current_proc->fds_lock);

    file_t *file = get_file_description(current_proc, fd, true);
    if (!file) {
        mutex_unlock(&current_proc->fds_lock);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    if (!exact) min = get_free_fd(current_proc, min);
    file_t *old = remove_fd(current_proc, min);
    int error = assign_fd(current_proc, min, file, flags);

    mutex_unlock(&current_proc->fds_lock);

    if (unlikely(error)) {
        ASSERT(old == NULL);
        file_deref(file);
        return SYSCALL_ERR(error);
    } else if (old != NULL) {
        file_deref(old);
    }

    return SYSCALL_NUM(min);
}

syscall_result_t sys_close(int fd) {
    if (fd < 0) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    mutex_lock(&current_proc->fds_lock);
    file_t *file = remove_fd(current_proc, fd);
    mutex_unlock(&current_proc->fds_lock);

    if (file) {
        file_deref(file);
        return SYSCALL_ERR(0);
    } else {
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }
}
