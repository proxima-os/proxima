#include "fs/vfs.h"
#include "proxima/compiler.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "hydrogen/limits.h"
#include "hydrogen/stat.h"
#include "hydrogen/vfs.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/panic.h"
#include <stdint.h>

static void unknown_file_free(file_t *self) {
    vmfree(self, sizeof(*self));
}

static const file_ops_t unknown_file_ops = {.free = unknown_file_free};

static int open_unknown_file(file_t **out) {
    file_t *handle = vmalloc(sizeof(*handle));
    if (unlikely(!handle)) return ERR_OUT_OF_MEMORY;
    memset(handle, 0, sizeof(*handle));

    handle->ops = &unknown_file_ops;
    handle->references = 1;

    *out = handle;
    return 0;
}

typedef struct {
    file_t base;
    uint64_t position;
} opened_regular_file_t;

static void opened_regular_file_free(file_t *ptr) {
    opened_regular_file_t *self = (opened_regular_file_t *)ptr;
    vmfree(self, sizeof(*self));
}

static int opened_regular_file_read(file_t *ptr, void *buffer, size_t *size) {
    opened_regular_file_t *self = (opened_regular_file_t *)ptr;
    vnode_t *vnode = self->base.vnode;

    mutex_lock(&vnode->lock);
    int error = vnode->ops->reg.read(vnode, buffer, size, self->position);
    self->position += *size;
    mutex_unlock(&vnode->lock);

    return error;
}

static int opened_regular_file_seek(file_t *ptr, uint64_t *offset, hydrogen_whence_t whence) {
    opened_regular_file_t *self = (opened_regular_file_t *)ptr;
    vnode_t *vnode = self->base.vnode;

    mutex_lock(&vnode->lock);

    uint64_t new_pos;
    switch (whence) {
    case HYDROGEN_WHENCE_SET: new_pos = 0; break;
    case HYDROGEN_WHENCE_CUR: new_pos = self->position; break;
    case HYDROGEN_WHENCE_END: {
        int error = vnode->ops->reg.get_size(vnode, &new_pos);
        if (unlikely(error)) {
            mutex_unlock(&vnode->lock);
            return error;
        }
        break;
    }
    }

    new_pos += *offset;
    self->position = new_pos;

    mutex_unlock(&vnode->lock);
    *offset = new_pos;
    return 0;
}

static int opened_regular_file_write(file_t *ptr, const void *buffer, size_t *size) {
    opened_regular_file_t *self = (opened_regular_file_t *)ptr;
    vnode_t *vnode = self->base.vnode;

    mutex_lock(&vnode->lock);

    if (self->base.mode & O_APPEND) {
        int error = vnode->ops->reg.get_size(vnode, &self->position);
        if (unlikely(error)) {
            mutex_unlock(&vnode->lock);
            return error;
        }
    }

    int error = vnode->ops->reg.write(vnode, buffer, size, self->position);
    self->position += *size;

    mutex_unlock(&vnode->lock);
    return error;
}

static int opened_regular_file_pread(file_t *ptr, void *buffer, size_t *size, uint64_t position) {
    vnode_t *vnode = ptr->vnode;
    mutex_lock(&vnode->lock);
    int error = vnode->ops->reg.read(vnode, buffer, size, position);
    mutex_unlock(&vnode->lock);
    return error;
}

static int opened_regular_file_pwrite(file_t *ptr, const void *buffer, size_t *size, uint64_t position) {
    vnode_t *vnode = ptr->vnode;
    mutex_lock(&vnode->lock);
    int error = vnode->ops->reg.write(vnode, buffer, size, position);
    mutex_unlock(&vnode->lock);
    return error;
}

static int opened_regular_file_mmap(file_t *ptr, uintptr_t *addr, size_t size, int flags, size_t offset) {
    vnode_t *vnode = ptr->vnode;
    mutex_lock(&vnode->lock);
    int error = vnode->ops->reg.mmap(vnode, addr, size, flags, offset);
    mutex_unlock(&vnode->lock);
    return error;
}

static const file_ops_t regular_file_ops = {
        .free = opened_regular_file_free,
        .read = opened_regular_file_read,
        .seek = opened_regular_file_seek,
        .write = opened_regular_file_write,
        .pread = opened_regular_file_pread,
        .pwrite = opened_regular_file_pwrite,
        .mmap = opened_regular_file_mmap,
};

static int open_regular_file(file_t **out) {
    opened_regular_file_t *handle = vmalloc(sizeof(*handle));
    if (unlikely(!handle)) return ERR_OUT_OF_MEMORY;
    memset(handle, 0, sizeof(*handle));

    handle->base.ops = &regular_file_ops;
    handle->base.references = 1;

    *out = &handle->base;
    return 0;
}

#define VFS_PARENT (1ul << 8)  // return the parent of the named file
#define VFS_PMAYBE (1ul << 9)  // if the named file doesn't exist, return its
#define VFS_NOLINK (1ul << 10) // if the path names a symlink, don't follow it
#define VFS_ALLOWF (1ul << 11) // skip the first access check

static void follow_mounts(vnode_t **vnode) {
    vnode_t *cur = *vnode;

    while (cur->mounted != NULL) {
        vnode_t *root = cur->mounted->root;
        vnode_ref(root);
        mutex_unlock(&cur->lock);
        vnode_deref(cur);
        mutex_lock(&root->lock);
        cur = root;
    }

    *vnode = cur;
}

// `base` must be locked on entry, this function unlocks it (even if it returns an error), returned vnode is locked
static int vfs_lookup(vnode_t *base, vnode_t **out, const void **path, size_t *length, int flags, ident_t *ident) {
    const char *name = *path;
    size_t len = *length;
    if (len == 0) return ERR_NOT_FOUND;

    vnode_t *root = get_root();

    if (name[0] == '/') {
        if (base) mutex_unlock(&base->lock);
        base = root;
        vnode_ref(base);
        mutex_lock(&base->lock);
        follow_mounts(&base);

        do {
            name++;
            len--;
        } while (len > 0 && name[0] == '/');
    } else if (base == NULL) {
        base = root;
        vnode_ref(base);
        mutex_lock(&base->lock);
    } else {
        vnode_ref(base);
    }

    while (len > 0) {
        if (base->type != VNODE_DIRECTORY) {
            mutex_unlock(&base->lock);
            vnode_deref(base);
            vnode_deref(root);
            return ERR_NOT_A_DIRECTORY;
        }

        if ((flags & VFS_ALLOWF) == 0 && !base->ops->access(base, S_IXOTH, ident)) {
            mutex_unlock(&base->lock);
            vnode_deref(base);
            vnode_deref(root);
            return ERR_ACCESS_DENIED;
        }

        flags &= ~VFS_ALLOWF;

        size_t nlen = 1;
        while (nlen < len && name[nlen] != '/') nlen++;

        size_t noff = nlen;
        while (noff < len && name[noff] == '/') noff++;

        if (nlen == len && (flags & (VFS_PARENT | VFS_NOLINK)) == (VFS_PARENT | VFS_NOLINK)) break;

        if (nlen != 1 || name[0] != '.') {
            bool is_dot_dot = nlen == 2 && name[0] == '.' && name[1] == '.';
            if (is_dot_dot && noff == len && (flags & VFS_PARENT) != 0) break;

            if (is_dot_dot) {
                vnode_t *cur = base;

                while (cur != root && cur == cur->vfs->root && cur->vfs->mountpoint) {
                    cur = cur->vfs->mountpoint;
                }

                if (cur != root) {
                    vnode_ref(cur);
                    mutex_unlock(&base->lock);
                    vnode_deref(base);
                    mutex_lock(&cur->lock);
                    base = cur;
                }
            }

            if (!is_dot_dot || base != base->vfs->root) {
                vnode_t *child;
                int error = base->ops->dir.lookup(base, &child, name, nlen);
                if (error) {
                    if (error == ERR_NOT_FOUND && noff == len && (flags & (VFS_PARENT | VFS_PMAYBE)) != 0) break;

                    mutex_unlock(&base->lock);
                    vnode_deref(base);
                    vnode_deref(root);
                    return error;
                }

                if (child->type == VNODE_SYMLINK && (nlen != len || (flags & VFS_NOLINK) == 0)) {
                    if (unlikely((flags & 0xff) == SYMLOOP_MAX)) {
                        mutex_unlock(&base->lock);
                        vnode_deref(base);
                        vnode_deref(child);
                        vnode_deref(root);
                        return ERR_TOO_MANY_SYMLINKS;
                    }

                    int lflags = (flags & ~VFS_NOLINK) + 1;
                    if (noff != len) lflags &= ~(VFS_PARENT | VFS_PMAYBE);

                    const void *target;
                    size_t target_len;
                    mutex_lock(&child->lock);
                    error = child->ops->link.read(child, &target, &target_len);
                    mutex_unlock(&child->lock);
                    if (unlikely(error)) {
                        mutex_unlock(&base->lock);
                        vnode_deref(base);
                        vnode_deref(root);
                        vnode_deref(child);
                        return error;
                    }

                    vnode_t *link = child;
                    error = vfs_lookup(base, &child, &target, &target_len, lflags, ident);
                    vnode_deref(link);
                    vnode_deref(base);
                    if (unlikely(error)) {
                        vnode_deref(root);
                        return error;
                    }

                    if (noff == len && (flags & VFS_PARENT) != 0) {
                        vnode_deref(root);
                        *out = child;
                        *path = target;
                        *length = target_len;
                        return 0;
                    }
                } else if (noff == len) {
                    if (noff != nlen && child->type != VNODE_DIRECTORY) {
                        mutex_unlock(&base->lock);
                        vnode_deref(base);
                        vnode_deref(child);
                        vnode_deref(root);
                        return ERR_NOT_A_DIRECTORY;
                    }

                    if (flags & VFS_PARENT) {
                        vnode_deref(child);
                        break;
                    }

                    mutex_unlock(&base->lock);
                    vnode_deref(base);
                    mutex_lock(&child->lock);
                } else {
                    mutex_unlock(&base->lock);
                    vnode_deref(base);
                    mutex_lock(&child->lock);
                }

                ASSERT(noff != len || (flags & VFS_PARENT) == 0);

                if (!is_dot_dot) follow_mounts(&child);
                base = child;
            }
        } else if (noff == len && (flags & VFS_PARENT) != 0) {
            break;
        }

        name += noff;
        len -= noff;
    }

    vnode_deref(root);

    *out = base;
    *path = name;
    *length = len;
    return 0;
}

static int lookup_rel(file_t *rel, vnode_t **out, const void **path, size_t *length, int flags, ident_t *ident) {
    if (rel) {
        if (!rel->vnode) return ERR_NOT_A_DIRECTORY;
        if (rel->mode & O_EXEC) flags |= VFS_ALLOWF;
        mutex_lock(&rel->vnode->lock);
        return vfs_lookup(rel->vnode, out, path, length, flags, ident);
    } else {
        return vfs_lookup(NULL, out, path, length, flags, ident);
    }
}

#define O_FMASK (O_APPEND | O_ACCMODE)

static int open_vnode(vnode_t *vnode, file_t **out, int flags) {
    if (vnode->type == VNODE_SYMLINK) {
        return ERR_TOO_MANY_SYMLINKS;
    } else if (vnode->type == VNODE_DIRECTORY) {
        if ((flags & (O_WRONLY | O_NODIR)) != 0 || (flags & (O_CREAT | O_DIRECTORY)) == O_CREAT) {
            return ERR_IS_A_DIRECTORY;
        }
    } else if (flags & O_DIRECTORY) {
        return ERR_NOT_A_DIRECTORY;
    }

    file_t *file;
    int error;

    switch (vnode->type) {
    case VNODE_DIRECTORY: error = vnode->ops->dir.open(vnode, &file); break;
    case VNODE_REGULAR:
        error = open_regular_file(&file);

        if (likely(error == 0) && (flags & O_TRUNC) != 0) {
            error = vnode->ops->reg.truncate(vnode, 0);
            if (unlikely(error)) {
                file_deref(file);
                return error;
            }
        }
        break;
    default: error = open_unknown_file(&file); break;
    }

    if (unlikely(error)) return error;

    file->mode = flags & O_FMASK;
    file->vnode = vnode;
    vnode_ref(vnode);
    *out = file;
    return 0;
}

#define O_MASK (O_CLOFORK | O_CLOEXEC | O_TRUNC | O_NOFOLLOW | O_NODIR | O_DIRECTORY | O_CREAT | O_FMASK)
#define S_MASK (S_ISUID | S_ISGID | S_ISVTX | S_IRWXUGO)

static void process_umask(uint32_t *mode) {
    *mode &= ~__atomic_load_n(&current_proc->umask, __ATOMIC_ACQUIRE);
}

static bool check_open_access(vnode_t *vnode, int flags, ident_t *ident) {
    int stat = 0;
    if (flags & O_RDONLY) stat |= S_IROTH;
    if (flags & O_WRONLY) stat |= S_IWOTH;
    if (flags & O_EXEC) stat |= S_IXOTH;
    return stat == 0 || vnode->ops->access(vnode, stat, ident);
}

uint32_t vfs_umask(uint32_t mask) {
    return __atomic_exchange_n(&current_proc->umask, mask & S_IRWXUGO, __ATOMIC_ACQ_REL);
}

int vfs_open(file_t *rel, file_t **out, const void *path, size_t path_len, int flags, uint32_t mode) {
    if (flags & ~O_MASK) return ERR_INVALID_ARGUMENT;
    if (mode & ~(S_IFMT | S_MASK)) return ERR_INVALID_ARGUMENT;
    process_umask(&mode);

    int lflags = 0;
    if (flags & O_CREAT) lflags |= (flags & O_EXCL) ? VFS_PARENT : VFS_PMAYBE;
    if (flags & (O_EXCL | O_NOFOLLOW)) lflags |= VFS_NOLINK;

    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, lflags, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    if (path_len != 0) {
        ASSERT(flags & O_CREAT);
        ASSERT(vnode->type == VNODE_DIRECTORY);

        const char *name = path;

        while (name[path_len - 1] == '/') {
            ASSERT(path_len >= 2);

            if (!(flags & O_DIRECTORY)) {
                mutex_unlock(&vnode->lock);
                vnode_deref(vnode);
                ident_deref(ident);
                return ERR_NOT_FOUND;
            }

            path_len -= 1;
        }

        if (!vnode->ops->access(vnode, S_IWOTH, ident)) {
            mutex_unlock(&vnode->lock);
            vnode_deref(vnode);
            ident_deref(ident);
            return ERR_ACCESS_DENIED;
        }

        if (flags & O_DIRECTORY) mode |= S_IFDIR;
        else mode |= S_IFREG;

        vnode_t *child;
        error = vnode->ops->dir.mknod(vnode, &child, name, path_len, mode, ident);
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);

        if (unlikely(error)) {
            ident_deref(ident);
            return error;
        }

        mutex_lock(&child->lock);
        vnode = child;
        flags &= ~O_TRUNC;
    } else {
        ASSERT((flags & O_EXCL) == 0);

        if (!check_open_access(vnode, flags, ident)) {
            mutex_unlock(&vnode->lock);
            vnode_deref(vnode);
            ident_deref(ident);
            return ERR_ACCESS_DENIED;
        }
    }

    error = open_vnode(vnode, out, flags);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    ident_deref(ident);
    return error;
}

int vfs_reopen(file_t *file, file_t **out, int flags) {
    vnode_t *vnode = file->vnode;
    if (!vnode) return ERR_INVALID_ARGUMENT;

    ident_t *ident = get_identity();
    mutex_lock(&vnode->lock);
    int error = check_open_access(vnode, flags, ident) ? open_vnode(vnode, out, flags) : ERR_ACCESS_DENIED;
    mutex_unlock(&vnode->lock);
    return error;
}

int vfs_mknod(file_t *rel, const void *path, size_t path_len, uint32_t mode) {
    if (mode & ~(S_IFMT | S_MASK)) return ERR_INVALID_ARGUMENT;
    if (S_ISLNK(mode)) return ERR_INVALID_ARGUMENT;
    process_umask(&mode);

    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, VFS_PMAYBE | VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    if (path_len == 0) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_ALREADY_EXISTS;
    }

    ASSERT(vnode->type == VNODE_DIRECTORY);

    const char *name = path;
    while (name[path_len - 1] == '/') {
        ASSERT(path_len >= 2);

        if (!S_ISDIR(mode)) {
            mutex_unlock(&vnode->lock);
            vnode_deref(vnode);
            ident_deref(ident);
            return ERR_NOT_FOUND;
        }

        path_len -= 1;
    }

    if (!vnode->ops->access(vnode, S_IWOTH, ident)) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_ACCESS_DENIED;
    }

    vnode_t *child;
    error = vnode->ops->dir.mknod(vnode, &child, name, path_len, mode, ident);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    ident_deref(ident);
    if (likely(error == 0)) vnode_deref(child);
    return error;
}

int vfs_symlink(file_t *rel, const void *path, size_t path_len, const void *target, size_t target_len) {
    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, VFS_PMAYBE | VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    if (path_len == 0) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_ALREADY_EXISTS;
    }

    ASSERT(vnode->type == VNODE_DIRECTORY);

    const char *name = path;
    if (name[path_len - 1] == '/') {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_NOT_FOUND;
    }

    if (!vnode->ops->access(vnode, S_IWOTH, ident)) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_ACCESS_DENIED;
    }

    error = vnode->ops->dir.symlink(vnode, name, path_len, target, target_len, ident);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    ident_deref(ident);
    return error;
}

int vfs_link(
        file_t *rel,
        const void *path,
        size_t path_len,
        file_t *trel,
        const void *tpath,
        size_t tlen,
        bool follow
) {
    ident_t *ident = get_identity();
    vnode_t *target;
    int error = lookup_rel(trel, &target, &tpath, &tlen, follow ? 0 : VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }
    mutex_unlock(&target->lock);

    vnode_t *dir;
    error = lookup_rel(rel, &dir, &path, &path_len, VFS_PMAYBE | VFS_NOLINK, ident);
    if (unlikely(error)) {
        vnode_deref(target);
        ident_deref(ident);
        return error;
    }

    if (path_len == 0) {
        mutex_unlock(&dir->lock);
        vnode_deref(dir);
        vnode_deref(target);
        ident_deref(ident);
        return ERR_ALREADY_EXISTS;
    }

    ASSERT(dir->type == VNODE_DIRECTORY);

    const char *name = path;
    if (name[path_len - 1] == '/') {
        mutex_unlock(&dir->lock);
        vnode_deref(dir);
        vnode_deref(target);
        ident_deref(ident);
        return ERR_NOT_FOUND;
    }

    if (!dir->ops->access(dir, S_IWOTH, ident)) {
        mutex_unlock(&dir->lock);
        vnode_deref(dir);
        vnode_deref(target);
        ident_deref(ident);
        return ERR_ACCESS_DENIED;
    }

    error = dir->ops->dir.link(dir, path, path_len, target);
    mutex_unlock(&dir->lock);
    vnode_deref(dir);
    vnode_deref(target);
    ident_deref(ident);
    return error;
}

static int verify_trailing_ok(vnode_t *dir, const void *path, size_t *length, bool must_exist, bool no_mountpoints) {
    const char *name = path;
    size_t nlen = *length;

    while (name[nlen - 1] == '/') {
        ASSERT(nlen >= 2);
        nlen -= 1;
    }

    if (nlen != *length || must_exist) {
        vnode_t *child;
        int error = dir->ops->dir.lookup(dir, &child, name, nlen);
        if (unlikely(error)) return error;

        if (nlen != *length && child->type != VNODE_DIRECTORY) {
            vnode_deref(child);
            return ERR_NOT_A_DIRECTORY;
        }

        if (no_mountpoints && child->mounted) {
            vnode_deref(child);
            return ERR_BUSY;
        }

        vnode_deref(child);
    }

    *length = nlen;
    return 0;
}

int vfs_unlink(file_t *rel, const void *path, size_t path_len, bool dir) {
    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, VFS_PARENT | VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    ASSERT(vnode->type == VNODE_DIRECTORY);
    ASSERT(path_len != 0);

    error = verify_trailing_ok(vnode, path, &path_len, true, true);
    if (unlikely(error)) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return error;
    }

    if (!vnode->ops->access(vnode, S_IWOTH, ident)) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_ACCESS_DENIED;
    }

    error = vnode->ops->dir.unlink(vnode, path, path_len, ident, dir);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    ident_deref(ident);
    return error;
}

int vfs_rename(file_t *rel, const void *path, size_t path_len, file_t *trel, const void *tpath, size_t tlen) {
    ident_t *ident = get_identity();
    vnode_t *srcdir;
    int error = lookup_rel(rel, &srcdir, &path, &path_len, VFS_PARENT | VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    ASSERT(srcdir->type == VNODE_DIRECTORY);
    ASSERT(path_len == 0);

    mutex_unlock(&srcdir->lock); // avoid deadlocks while resolving target

    vnode_t *dstdir;
    error = lookup_rel(trel, &dstdir, &tpath, &tlen, VFS_PARENT | VFS_NOLINK, ident);
    if (unlikely(error)) {
        vnode_deref(srcdir);
        ident_deref(ident);
        return error;
    }

    ASSERT(dstdir->type == VNODE_DIRECTORY);
    ASSERT(tlen != 0);

    if (dstdir->vfs != srcdir->vfs) {
        mutex_unlock(&dstdir->lock);
        vnode_deref(srcdir);
        vnode_deref(dstdir);
        ident_deref(ident);
        return ERR_DIFFERENT_FILESYSTEMS;
    }

    error = verify_trailing_ok(dstdir, tpath, &tlen, true, true);
    if (unlikely(error)) {
        mutex_unlock(&dstdir->lock);
        vnode_deref(srcdir);
        vnode_deref(dstdir);
        ident_deref(ident);
        return error;
    }

    mutex_lock(&srcdir->lock);

    error = verify_trailing_ok(srcdir, path, &path_len, true, true);
    if (unlikely(error)) {
        mutex_unlock(&srcdir->lock);
        mutex_unlock(&dstdir->lock);
        vnode_deref(srcdir);
        vnode_deref(dstdir);
        ident_deref(ident);
        return error;
    }

    if (!srcdir->ops->access(srcdir, S_IWOTH, ident) || !dstdir->ops->access(dstdir, S_IWOTH, ident)) {
        mutex_unlock(&srcdir->lock);
        mutex_unlock(&dstdir->lock);
        vnode_deref(srcdir);
        vnode_deref(dstdir);
        ident_deref(ident);
        return ERR_ACCESS_DENIED;
    }

    error = srcdir->ops->dir.rename(srcdir, path, path_len, dstdir, tpath, tlen, ident);
    mutex_unlock(&srcdir->lock);
    mutex_unlock(&dstdir->lock);
    vnode_deref(srcdir);
    vnode_deref(dstdir);
    ident_deref(ident);
    return ERR_ACCESS_DENIED;
}

int vfs_truncate(file_t *rel, const void *path, size_t path_len, uint64_t size) {
    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, 0, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    if (!vnode->ops->access(vnode, S_IWOTH, ident)) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return ERR_ACCESS_DENIED;
    }

    if (vnode->type != VNODE_REGULAR) {
        error = vnode->type == VNODE_DIRECTORY ? ERR_IS_A_DIRECTORY : ERR_INVALID_ARGUMENT;
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        ident_deref(ident);
        return error;
    }

    error = vnode->ops->reg.truncate(vnode, size);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    ident_deref(ident);
    return error;
}

int vfs_ftruncate(file_t *rel, uint64_t size) {
    if ((rel->mode & O_WRONLY) == 0) return ERR_INVALID_HANDLE;

    vnode_t *vnode = rel->vnode;
    if (!vnode || vnode->type != VNODE_REGULAR) return ERR_INVALID_ARGUMENT;

    mutex_lock(&vnode->lock);
    int error = vnode->ops->reg.truncate(vnode, size);
    mutex_unlock(&vnode->lock);
    return error;
}

static int do_stat(vnode_t *vnode, hydrogen_stat_t *out) {
    int error = vnode->ops->stat(vnode, out);
    if (likely(error == 0)) {
        out->fs = vnode->vfs->id;
        out->id = vnode->id;
    }
    return error;
}

int vfs_stat(file_t *rel, const void *path, size_t path_len, hydrogen_stat_t *out, bool follow) {
    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, follow ? 0 : VFS_NOLINK, ident);
    ident_deref(ident);
    if (unlikely(error)) return error;

    error = do_stat(vnode, out);
    mutex_unlock(&vnode->lock);
    return error;
}

int vfs_fstat(file_t *file, hydrogen_stat_t *out) {
    if (file->ops->stat) return file->ops->stat(file, out);

    vnode_t *vnode = file->vnode;
    if (!vnode) return ERR_NOT_IMPLEMENTED;

    mutex_lock(&vnode->lock);
    int error = do_stat(vnode, out);
    mutex_unlock(&vnode->lock);
    return error;
}

int vfs_readlink(file_t *rel, const void *path, size_t path_len, void *buf, size_t *buf_len) {
    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, VFS_NOLINK, ident);
    ident_deref(ident);
    if (unlikely(error)) return error;

    if (vnode->type != VNODE_SYMLINK) {
        mutex_unlock(&vnode->lock);
        vnode_deref(vnode);
        return ERR_INVALID_ARGUMENT;
    }

    const void *target;
    size_t targ_len;
    error = vnode->ops->link.read(vnode, &target, &targ_len);
    mutex_unlock(&vnode->lock);

    if (unlikely(error)) {
        vnode_deref(vnode);
        return error;
    }

    size_t copy_len = *buf_len;
    if (targ_len < copy_len) copy_len = targ_len;

    error = memcpy_user(buf, target, copy_len);
    vnode_deref(vnode);
    *buf_len = targ_len;
    return error;
}

int vfs_seek(file_t *file, uint64_t *offset, hydrogen_whence_t whence) {
    if (!file->ops->seek) return ERR_NOT_IMPLEMENTED;

    return file->ops->seek(file, offset, whence);
}

int vfs_read(file_t *file, void *buffer, size_t *size, int read_flag) {
    if ((file->mode & read_flag) == 0) return ERR_INVALID_HANDLE;
    if (!file->ops->read) return ERR_NOT_IMPLEMENTED;
    if (*size == 0) return 0;

    return file->ops->read(file, buffer, size);
}

int vfs_write(file_t *file, const void *buffer, size_t *size) {
    if ((file->mode & O_WRONLY) == 0) return ERR_INVALID_HANDLE;
    if (!file->ops->write) return ERR_NOT_IMPLEMENTED;
    if (*size == 0) return 0;

    return file->ops->write(file, buffer, size);
}

int vfs_pread(file_t *file, void *buffer, size_t *size, uint64_t position, int read_flag) {
    if ((file->mode & read_flag) == 0) return ERR_INVALID_HANDLE;
    if (!file->ops->pread) return ERR_NOT_IMPLEMENTED;
    if (*size == 0) return 0;

    return file->ops->pread(file, buffer, size, position);
}

int vfs_pwrite(file_t *file, const void *buffer, size_t *size, uint64_t position) {
    if ((file->mode & O_WRONLY) == 0) return ERR_INVALID_HANDLE;
    if (!file->ops->pwrite) return ERR_NOT_IMPLEMENTED;
    if (*size == 0) return 0;

    return file->ops->pwrite(file, buffer, size, position);
}

int vfs_mmap(file_t *file, uintptr_t *addr, size_t size, int flags, size_t offset, int rflag) {
    if ((file->mode & rflag) == 0) return ERR_ACCESS_DENIED;
    if ((flags & (VMM_WRITE | VMM_PRIVATE)) == VMM_WRITE && (file->mode & O_WRONLY) == 0) return ERR_ACCESS_DENIED;
    if (!file->ops->mmap) return ERR_NOT_IMPLEMENTED;

    return file->ops->mmap(file, addr, size, flags, offset);
}

int vfs_utimes(file_t *rel, const void *path, size_t path_len, int64_t atime, int64_t mtime, bool follow) {
    if (atime == INT64_MIN && mtime == INT64_MIN) return 0;

    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, follow ? 0 : VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    error = vnode->ops->utimes(vnode, atime, mtime, ident);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    return error;
}

int vfs_futimes(file_t *file, int64_t atime, int64_t mtime) {
    if (atime == INT64_MAX && mtime == INT64_MIN) return 0;

    ident_t *ident = get_identity();
    int error;

    if (file->ops->utimes) {
        error = file->ops->utimes(file, atime, mtime, ident);
    } else {
        vnode_t *vnode = file->vnode;

        if (vnode) {
            mutex_lock(&vnode->lock);
            error = vnode->ops->utimes(vnode, atime, mtime, ident);
            mutex_unlock(&vnode->lock);
        } else {
            error = ERR_NOT_IMPLEMENTED;
        }
    }

    ident_deref(ident);
    return error;
}

int vfs_chown(file_t *rel, const void *path, size_t path_len, uint32_t uid, uint32_t gid, bool follow) {
    if (uid == UINT32_MAX && gid == UINT32_MAX) return 0;

    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, follow ? 0 : VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    error = vnode->ops->chown(vnode, uid, gid, ident);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    return error;
}

int vfs_fchown(file_t *file, uint32_t uid, uint32_t gid) {
    if (uid == UINT32_MAX && gid == UINT32_MAX) return 0;

    ident_t *ident = get_identity();
    int error;

    if (file->ops->chown) {
        error = file->ops->chown(file, uid, gid, ident);
    } else {
        vnode_t *vnode = file->vnode;

        if (vnode) {
            mutex_lock(&vnode->lock);
            error = vnode->ops->chown(vnode, uid, gid, ident);
            mutex_unlock(&vnode->lock);
        } else {
            error = ERR_NOT_IMPLEMENTED;
        }
    }

    ident_deref(ident);
    return error;
}

int vfs_chmod(file_t *rel, const void *path, size_t path_len, uint32_t mode, bool follow) {
    if (mode & ~(S_IFMT | S_MASK)) return ERR_INVALID_ARGUMENT;

    ident_t *ident = get_identity();
    vnode_t *vnode;
    int error = lookup_rel(rel, &vnode, &path, &path_len, follow ? 0 : VFS_NOLINK, ident);
    if (unlikely(error)) {
        ident_deref(ident);
        return error;
    }

    error = vnode->ops->chmod(vnode, mode, ident);
    mutex_unlock(&vnode->lock);
    vnode_deref(vnode);
    return error;
}

int vfs_fchmod(file_t *file, uint32_t mode) {
    if (mode & ~(S_IFMT | S_MASK)) return ERR_INVALID_ARGUMENT;

    ident_t *ident = get_identity();
    int error;

    if (file->ops->chmod) {
        error = file->ops->chmod(file, mode, ident);
    } else {
        vnode_t *vnode = file->vnode;

        if (vnode) {
            mutex_lock(&vnode->lock);
            error = vnode->ops->chmod(vnode, mode, ident);
            mutex_unlock(&vnode->lock);
        } else {
            error = ERR_NOT_IMPLEMENTED;
        }
    }

    ident_deref(ident);
    return error;
}

uint64_t get_vfs_id(void) {
    static uint64_t next;
    return __atomic_fetch_add(&next, 1, __ATOMIC_RELAXED);
}

int get_mountpoint_parent(vfs_t *vfs, vnode_t **out) {
    vnode_t *root = get_root();
    vnode_t *cur = vfs->root;

    while (cur != root && cur == vfs->root && cur->vfs->mountpoint != NULL) {
        cur = cur->vfs->mountpoint;
    }

    vnode_deref(root);

    if (cur == root) {
        *out = vfs->root;
        vnode_ref(*out);
        return 0;
    }

    ASSERT(cur->type == VNODE_DIRECTORY);
    return cur->ops->dir.lookup(cur, out, "..", 2);
}

void file_ref(file_t *file) {
    __atomic_fetch_add(&file->references, 1, __ATOMIC_ACQ_REL);
}

void file_deref(file_t *file) {
    if (__atomic_fetch_sub(&file->references, 1, __ATOMIC_ACQ_REL) == 1) {
        vnode_t *vnode = file->vnode;
        file->ops->free(file);
        if (vnode) vnode_deref(vnode);
    }
}

void vnode_ref(vnode_t *vnode) {
    __atomic_fetch_add(&vnode->references, 1, __ATOMIC_ACQ_REL);
}

void vnode_deref(vnode_t *vnode) {
    if (__atomic_fetch_sub(&vnode->references, 1, __ATOMIC_ACQ_REL) == 1) {
        vnode->ops->free(vnode);
    }
}
