#ifndef HYDROGEN_SYS_SYSVECS_H
#define HYDROGEN_SYS_SYSVECS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    union {
        size_t num;
        void *ptr;
    } value;
    int error;
} syscall_result_t;

typedef enum {
    SYS_EXIT,
    SYS_MMAP,
    SYS_MPROTECT,
    SYS_MUNMAP,
    SYS_GET_FS_BASE,
    SYS_GET_GS_BASE,
    SYS_SET_FS_BASE,
    SYS_SET_GS_BASE,
    SYS_UMASK,
    SYS_OPEN,
    SYS_REOPEN,
    SYS_DUP,
    SYS_CLOSE,
    SYS_MKNOD,
    SYS_SYMLINK,
    SYS_LINK,
    SYS_UNLINK,
    SYS_RENAME,
    SYS_READLINK,
    SYS_STAT,
    SYS_FSTAT,
    SYS_TRUNCATE,
    SYS_FTRUNCATE,
    SYS_UTIMES,
    SYS_FUTIMES,
    SYS_CHOWN,
    SYS_FCHOWN,
    SYS_CHMOD,
    SYS_FCHMOD,
    SYS_SEEK,
    SYS_READ,
    SYS_WRITE,
    SYS_PREAD,
    SYS_PWRITE,
    SYS_EXECVE,
    SYS_FEXECVE,
} syscall_vector_t;

typedef struct {
    int source_rel;
    const void *source_name;
    size_t source_length;

    int target_rel;
    const void *target_name;
    size_t target_length;

    bool follow_symlinks;
} sys_link_args_t;

typedef struct {
    const void **argv;
    size_t *arg_sizes;
    size_t argv_count;

    const void **envp;
    size_t *env_sizes;
    size_t envp_count;
} sys_execve_args_t;

#endif // HYDROGEN_SYS_SYSVECS_H
