#ifndef HYDROGEN_SYS_SYSCALL_H
#define HYDROGEN_SYS_SYSCALL_H

#include "fs/vfs.h"
#include "hydrogen/stat.h"
#include "hydrogen/vfs.h"
#include "sys/sysvecs.h"
#include <stdbool.h>
#include <stdint.h>

#define SYSCALL_NUM(val) ((syscall_result_t){.value.num = (val)})
#define SYSCALL_PTR(val) ((syscall_result_t){.value.ptr = (val)})
#define SYSCALL_ERR(err) ((syscall_result_t){.error = (err)})

extern int (*memcpy_user)(void *, const void *, size_t);
extern int (*memset_user)(void *, int, size_t);

void syscall_init(void);

int verify_user_ptr(const void *ptr, size_t len);
int verify_addr(uintptr_t addr);
int copy_to_heap(void **buffer, const void *src, size_t size);
int fd_to_file_opt(int fd, file_t **out);

_Noreturn void hydrogen_exit(void);

syscall_result_t sys_mmap(uintptr_t addr, size_t size, int flags, int fd, size_t offset);
syscall_result_t sys_mprotect(uintptr_t addr, size_t size, int flags);
syscall_result_t sys_munmap(uintptr_t addr, size_t size);
syscall_result_t sys_get_fs_base(void);
syscall_result_t sys_get_gs_base(void);
syscall_result_t sys_set_fs_base(uintptr_t base);
syscall_result_t sys_set_gs_base(uintptr_t base);

syscall_result_t sys_umask(uint32_t mask);

syscall_result_t sys_open(int fd, const void *path, size_t path_len, int flags, uint32_t mode);
syscall_result_t sys_reopen(int fd, int flags);
syscall_result_t sys_dup(int fd, int min, int flags, bool exact);
syscall_result_t sys_close(int fd);

syscall_result_t sys_mknod(int fd, const void *path, size_t path_len, uint32_t mode);
syscall_result_t sys_symlink(int fd, const void *path, size_t path_len, const void *target, size_t target_len);
syscall_result_t sys_link(const sys_link_args_t *args);
syscall_result_t sys_unlink(int fd, const void *path, size_t path_len, bool dir);
syscall_result_t sys_rename(int sfd, const void *spath, size_t slen, int tfd, const void *tpath, size_t tlen);

syscall_result_t sys_readlink(int fd, const void *path, size_t path_len, void *buf, size_t buf_len);
syscall_result_t sys_stat(int fd, const void *path, size_t path_len, hydrogen_stat_t *out, bool follow);
syscall_result_t sys_fstat(int fd, hydrogen_stat_t *out);

syscall_result_t sys_truncate(int fd, const void *path, size_t path_len, uint64_t size);
syscall_result_t sys_ftruncate(int fd, uint64_t size);
syscall_result_t sys_utimes(int fd, const void *path, size_t path_len, int64_t atime, int64_t mtime, bool follow);
syscall_result_t sys_futimes(int fd, int64_t atime, int64_t mtime);
syscall_result_t sys_chown(int fd, const void *path, size_t path_len, uint32_t uid, uint32_t gid, bool follow);
syscall_result_t sys_fchown(int fd, uint32_t uid, uint32_t gid);
syscall_result_t sys_chmod(int fd, const void *path, size_t path_len, uint32_t mode, bool follow);
syscall_result_t sys_fchmod(int fd, uint32_t mode);

syscall_result_t sys_seek(int fd, uint64_t offset, hydrogen_whence_t whence);
syscall_result_t sys_read(int fd, void *buf, size_t size);
syscall_result_t sys_write(int fd, const void *buf, size_t size);
syscall_result_t sys_pread(int fd, void *buf, size_t size, uint64_t position);
syscall_result_t sys_pwrite(int fd, const void *buf, size_t size, uint64_t position);

syscall_result_t sys_execve(int fd, const void *path, size_t path_len, const sys_execve_args_t *args);
syscall_result_t sys_fexecve(int fd, const sys_execve_args_t *args);

#endif // HYDROGEN_SYS_SYSCALL_H
