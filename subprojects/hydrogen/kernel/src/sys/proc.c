#include "sched/proc.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "mem/vheap.h"
#include "proxima/compiler.h"
#include "sched/exec.h"
#include "string.h"
#include "sys/syscall.h"
#include "sys/sysvecs.h"

static int create_execve_strings(execve_string_t **out, const void **ptrs, size_t *sizes, size_t count) {
    int error = verify_user_ptr(ptrs, sizeof(*ptrs) * count);
    if (unlikely(error)) return error;

    error = verify_user_ptr(sizes, sizeof(*sizes) * count);
    if (unlikely(error)) return error;

    execve_string_t *buf = vmalloc(sizeof(*buf) * count);
    if (unlikely(!buf)) return ERR_OUT_OF_MEMORY;
    memset(buf, 0, sizeof(*buf) * count);

    for (size_t i = 0; i < count; i++) {
        size_t len = sizes[i];
        error = copy_to_heap(&buf[i].data, ptrs[i], len);
        if (unlikely(error)) {
            cleanup_execve_strings(buf, count);
            return error;
        }
        buf[i].length = len;
    }

    *out = buf;
    return 0;
}

static syscall_result_t do_execve(file_t *file, const sys_execve_args_t *argsrc) {
    int error = verify_user_ptr(argsrc, sizeof(*argsrc));
    if (unlikely(error)) return SYSCALL_ERR(error);

    sys_execve_args_t args;
    error = memcpy_user(&args, argsrc, sizeof(args));
    if (unlikely(error)) return SYSCALL_ERR(error);

    execve_string_t *argv, *envp;
    error = create_execve_strings(&argv, args.argv, args.arg_sizes, args.argv_count);
    if (unlikely(error)) return SYSCALL_ERR(error);

    error = create_execve_strings(&envp, args.envp, args.env_sizes, args.envp_count);
    if (unlikely(error)) {
        cleanup_execve_strings(argv, args.argv_count);
        return SYSCALL_ERR(error);
    }

    return SYSCALL_ERR(execve(file, argv, args.argv_count, envp, args.envp_count));
}

syscall_result_t sys_execve(int fd, const void *path, size_t path_len, const sys_execve_args_t *args) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    file_t *file;
    error = vfs_open(rel, &file, kpath, path_len, O_EXEC | O_NODIR, 0);
    file_deref(rel);
    vmfree(kpath, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    syscall_result_t result = do_execve(file, args);
    file_deref(file);
    return result;
}

syscall_result_t sys_fexecve(int fd, const sys_execve_args_t *args) {
    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    syscall_result_t result = do_execve(file, args);
    file_deref(file);
    return result;
}
