#include "fs/vfs.h"
#include "proxima/compiler.h"
#include "hydrogen/error.h"
#include "hydrogen/stat.h"
#include "mem/vheap.h"
#include "sched/proc.h"
#include "sys/syscall.h"
#include "sys/sysvecs.h"

syscall_result_t sys_umask(uint32_t mask) {
    return SYSCALL_NUM(vfs_umask(mask));
}

syscall_result_t sys_mknod(int fd, const void *path, size_t path_len, uint32_t mode) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_mknod(rel, path, path_len, mode);
    file_deref(rel);
    vmfree(kpath, path_len);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_symlink(int fd, const void *spath, size_t slen, const void *tpath, size_t tlen) {
    void *kspath;
    int error = copy_to_heap(&kspath, spath, slen);
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *ktpath;
    error = copy_to_heap(&ktpath, tpath, tlen);
    if (unlikely(error)) {
        vmfree(kspath, slen);
        return SYSCALL_ERR(error);
    }

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kspath, slen);
        vmfree(ktpath, tlen);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_symlink(rel, spath, slen, ktpath, tlen);
    file_deref(rel);
    vmfree(kspath, slen);
    vmfree(ktpath, tlen);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_link(const sys_link_args_t *args_ptr) {
    int error = verify_user_ptr(args_ptr, sizeof(*args_ptr));
    if (unlikely(error)) return SYSCALL_ERR(error);

    sys_link_args_t args;
    error = memcpy_user(&args, args_ptr, sizeof(args));
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *kspath;
    error = copy_to_heap(&kspath, args.source_name, args.source_length);
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *ktpath;
    error = copy_to_heap(&ktpath, args.target_name, args.target_length);
    if (unlikely(error)) {
        vmfree(kspath, args.source_length);
        return SYSCALL_ERR(error);
    }

    file_t *srel;
    error = fd_to_file_opt(args.source_rel, &srel);
    if (unlikely(error)) {
        vmfree(kspath, args.source_length);
        vmfree(ktpath, args.target_length);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    file_t *trel;
    error = fd_to_file_opt(args.target_rel, &trel);
    if (unlikely(error)) {
        file_deref(srel);
        vmfree(kspath, args.source_length);
        vmfree(ktpath, args.target_length);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_link(srel, kspath, args.source_length, trel, ktpath, args.target_length, args.follow_symlinks);
    file_deref(srel);
    file_deref(trel);
    vmfree(kspath, args.source_length);
    vmfree(ktpath, args.target_length);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_unlink(int fd, const void *path, size_t path_len, bool dir) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_unlink(rel, path, path_len, dir);
    file_deref(rel);
    vmfree(kpath, path_len);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_rename(int sfd, const void *spath, size_t slen, int tfd, const void *tpath, size_t tlen) {
    void *kspath;
    int error = copy_to_heap(&kspath, spath, slen);
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *ktpath;
    error = copy_to_heap(&ktpath, tpath, tlen);
    if (unlikely(error)) {
        vmfree(kspath, slen);
        return SYSCALL_ERR(error);
    }

    file_t *srel;
    error = fd_to_file_opt(sfd, &srel);
    if (unlikely(error)) {
        vmfree(kspath, slen);
        vmfree(ktpath, tlen);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    file_t *trel;
    error = fd_to_file_opt(tfd, &trel);
    if (unlikely(error)) {
        file_deref(srel);
        vmfree(kspath, slen);
        vmfree(ktpath, tlen);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_rename(srel, kspath, slen, trel, ktpath, tlen);
    file_deref(srel);
    file_deref(trel);
    vmfree(kspath, slen);
    vmfree(ktpath, tlen);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_readlink(int fd, const void *path, size_t path_len, void *buf, size_t buf_len) {
    int error = verify_user_ptr(buf, buf_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *kpath;
    error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_readlink(rel, path, path_len, buf, &buf_len);
    file_deref(rel);
    vmfree(kpath, path_len);
    return likely(!error) ? SYSCALL_NUM(buf_len) : SYSCALL_ERR(error);
}

syscall_result_t sys_stat(int fd, const void *path, size_t path_len, hydrogen_stat_t *out, bool follow) {
    int error = verify_user_ptr(out, sizeof(*out));
    if (unlikely(error)) return SYSCALL_ERR(error);

    void *kpath;
    error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    hydrogen_stat_t buf;
    error = vfs_stat(rel, path, path_len, &buf, follow);
    file_deref(rel);
    vmfree(kpath, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    error = memcpy_user(out, &buf, sizeof(buf));
    return SYSCALL_ERR(error);
}

syscall_result_t sys_fstat(int fd, hydrogen_stat_t *out) {
    int error = verify_user_ptr(out, sizeof(*out));
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    hydrogen_stat_t buf;
    error = vfs_fstat(file, &buf);
    file_deref(file);
    if (unlikely(error)) return SYSCALL_ERR(error);

    error = memcpy_user(out, &buf, sizeof(buf));
    return SYSCALL_ERR(error);
}

syscall_result_t sys_truncate(int fd, const void *path, size_t path_len, uint64_t size) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_truncate(rel, path, path_len, size);
    file_deref(rel);
    vmfree(kpath, path_len);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_ftruncate(int fd, uint64_t size) {
    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    int error = vfs_ftruncate(file, size);
    file_deref(file);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_utimes(int fd, const void *path, size_t path_len, int64_t atime, int64_t mtime, bool follow) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_utimes(rel, path, path_len, atime, mtime, follow);
    file_deref(rel);
    vmfree(kpath, path_len);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_futimes(int fd, int64_t atime, int64_t mtime) {
    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    int error = vfs_futimes(file, atime, mtime);
    file_deref(file);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_chown(int fd, const void *path, size_t path_len, uint32_t uid, uint32_t gid, bool follow) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_chown(rel, path, path_len, uid, gid, follow);
    file_deref(rel);
    vmfree(kpath, path_len);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_fchown(int fd, uint32_t uid, uint32_t gid) {
    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    int error = vfs_fchown(file, uid, gid);
    file_deref(file);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_chmod(int fd, const void *path, size_t path_len, uint32_t mode, bool follow) {
    void *kpath;
    int error = copy_to_heap(&kpath, path, path_len);
    if (unlikely(error)) return SYSCALL_ERR(error);

    file_t *rel;
    error = fd_to_file_opt(fd, &rel);
    if (unlikely(error)) {
        vmfree(kpath, path_len);
        return SYSCALL_ERR(ERR_INVALID_HANDLE);
    }

    error = vfs_chmod(rel, path, path_len, mode, follow);
    file_deref(rel);
    vmfree(kpath, path_len);
    return SYSCALL_ERR(error);
}

syscall_result_t sys_fchmod(int fd, uint32_t mode) {
    file_t *file = get_file_description(current_proc, fd, false);
    if (unlikely(!file)) return SYSCALL_ERR(ERR_INVALID_HANDLE);

    int error = vfs_fchmod(file, mode);
    file_deref(file);
    return SYSCALL_ERR(error);
}
