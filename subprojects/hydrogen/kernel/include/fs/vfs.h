#ifndef HYDROGEN_FS_VFS_H
#define HYDROGEN_FS_VFS_H

#include "hydrogen/dirent.h"
#include "hydrogen/stat.h"
#include "hydrogen/vfs.h"
#include "sched/mutex.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct file file_t;
typedef struct ident ident_t;
typedef struct vfs vfs_t;
typedef struct vnode vnode_t;

typedef struct {
    void (*free)(file_t *self);
    // if these are null, fall back to the equivalent op on the vnode
    int (*stat)(file_t *self, hydrogen_stat_t *out);
    int (*utimes)(file_t *self, int64_t atime, int64_t mtime, ident_t *ident);
    int (*chown)(file_t *self, uint32_t uid, uint32_t gid, ident_t *ident);
    int (*chmod)(file_t *self, uint32_t mode, ident_t *ident);
    // for directories: read as many `hydrogen_dirent_t` structures into `buffer` as possible. return ERR_OVERFLOW if
    //                  it can't even fit one
    // for everything else: read as many bytes into `buffer` as possible
    // if only partially failed, return success first and an error on the next call (which should be a full failure)
    int (*read)(file_t *self, void *buffer, size_t *size);
    // for directories: unit is filesystem-defined, but when offset is 0 it must work as expected for the given whence
    // for everything else: unit is bytes
    // the absolute new position is returned in `offset`
    int (*seek)(file_t *self, uint64_t *offset, hydrogen_whence_t whence);
    int (*write)(file_t *self, const void *buffer, size_t *size);
    int (*pread)(file_t *self, void *buffer, size_t *size, uint64_t position);
    int (*pwrite)(file_t *self, const void *buffer, size_t *size, uint64_t position);
    int (*mmap)(file_t *self, uintptr_t *addr, size_t size, int flags, size_t offset);
} file_ops_t;

struct file {
    const file_ops_t *ops;
    size_t references;
    vnode_t *vnode;
    int mode;
};

struct vfs {
    uint64_t id;
    vnode_t *mountpoint;
    vnode_t *root;
};

typedef enum {
    VNODE_UNKNOWN,
    VNODE_DIRECTORY,
    VNODE_SYMLINK,
    VNODE_REGULAR,
    VNODE_CHAR_DEV,
    VNODE_BLOCK_DEV,
    VNODE_FIFO,
    VNODE_SOCKET,
} vnode_type_t;

typedef struct {
    void (*free)(vnode_t *self);
    // `mask` is the mask of the mode bits that should be set if the relation to this vnode is other
    // e.g. if checking for write and execute access it'll be S_IWOTH | S_IXOTH
    bool (*access)(vnode_t *self, uint32_t mask, ident_t *ident);
    int (*stat)(vnode_t *self, hydrogen_stat_t *out);
    int (*utimes)(vnode_t *self, int64_t atime, int64_t mtime, ident_t *ident);
    int (*chown)(vnode_t *self, uint32_t uid, uint32_t gid, ident_t *ident);
    int (*chmod)(vnode_t *self, uint32_t mode, ident_t *ident);
    union {
        struct {
            int (*open)(vnode_t *self, file_t **out);
            int (*lookup)(vnode_t *self, vnode_t **out, const void *name, size_t length);
            // if this returns 0 or ERR_ALREADY_EXISTS, out is set to the vnode
            int (*mknod)(vnode_t *self, vnode_t **out, const void *name, size_t length, uint32_t mode, ident_t *ident);
            int (*symlink)(
                    vnode_t *self,
                    const void *name,
                    size_t length,
                    const void *target,
                    size_t target_length,
                    ident_t *ident
            );
            int (*link)(vnode_t *self, const void *name, size_t length, vnode_t *target);
            int (*unlink)(vnode_t *self, const void *name, size_t length, ident_t *ident, bool dir);
            // src and dest are both locked
            int (*rename)(
                    vnode_t *src,
                    const void *src_name,
                    size_t src_length,
                    vnode_t *dest,
                    const void *dest_name,
                    size_t dest_length,
                    ident_t *ident
            );
        } dir;
        struct {
            // target must remain valid for the remainder of the vnode's lifetime
            int (*read)(vnode_t *self, const void **target, size_t *target_len);
        } link;
        struct {
            int (*truncate)(vnode_t *self, uint64_t size);
            // used for SEEK_END and O_APPEND
            int (*get_size)(vnode_t *self, uint64_t *out);
            // read as many bytes as possible into buffer from position, and set size to the number of read bytes.
            // note that setting the number of read bytes is always done, even if an error is returned
            int (*read)(vnode_t *self, void *buffer, size_t *size, uint64_t position);
            // write as many bytes as possible from buffer into position, and set size to the number of written bytes.
            // note that setting the number of written bytes is always done, even if an error is returned
            int (*write)(vnode_t *self, const void *buffer, size_t *size, uint64_t position);
            int (*mmap)(vnode_t *self, uintptr_t *addr, size_t size, int flags, size_t offset);
        } reg;
    };
} vnode_ops_t;

struct vnode {
    const vnode_ops_t *ops;
    size_t references;
    vfs_t *vfs;
    uint64_t id;
    vnode_type_t type;

    mutex_t lock;
    vfs_t *mounted;
};

uint32_t vfs_umask(uint32_t mask);

int vfs_open(file_t *rel, file_t **out, const void *path, size_t path_len, int flags, uint32_t mode);
int vfs_reopen(file_t *file, file_t **out, int flags);

int vfs_mknod(file_t *rel, const void *path, size_t path_len, uint32_t mode);
int vfs_symlink(file_t *rel, const void *path, size_t path_len, const void *target, size_t target_len);
int vfs_link(file_t *rel, const void *path, size_t path_len, file_t *trel, const void *tpath, size_t tlen, bool follow);
int vfs_unlink(file_t *rel, const void *path, size_t path_len, bool dir);
int vfs_rename(file_t *rel, const void *path, size_t path_len, file_t *trel, const void *tpath, size_t tlen);

int vfs_readlink(file_t *rel, const void *path, size_t path_len, void *buf, size_t *buf_len);
int vfs_stat(file_t *rel, const void *path, size_t path_len, hydrogen_stat_t *out, bool follow);
int vfs_fstat(file_t *file, hydrogen_stat_t *out);

int vfs_truncate(file_t *rel, const void *path, size_t path_len, uint64_t size);
int vfs_ftruncate(file_t *rel, uint64_t size);
int vfs_utimes(file_t *rel, const void *path, size_t path_len, int64_t atime, int64_t mtime, bool follow);
int vfs_futimes(file_t *file, int64_t atime, int64_t mtime);
int vfs_chown(file_t *rel, const void *path, size_t path_len, uint32_t uid, uint32_t gid, bool follow);
int vfs_fchown(file_t *file, uint32_t uid, uint32_t gid);
int vfs_chmod(file_t *rel, const void *path, size_t path_len, uint32_t mode, bool follow);
int vfs_fchmod(file_t *file, uint32_t mode);

int vfs_seek(file_t *file, uint64_t *offset, hydrogen_whence_t whence);
int vfs_read(file_t *file, void *buffer, size_t *size, int read_flag);
int vfs_write(file_t *file, const void *buffer, size_t *size);
int vfs_pread(file_t *file, void *buffer, size_t *size, uint64_t position, int read_flag);
int vfs_pwrite(file_t *file, const void *buffer, size_t *size, uint64_t position);
int vfs_mmap(file_t *file, uintptr_t *addr, size_t size, int flags, size_t offset, int rflag);

uint64_t get_vfs_id(void);

// you must own vfs->root->lock
int get_mountpoint_parent(vfs_t *vfs, vnode_t **out);

void file_ref(file_t *file);

void file_deref(file_t *file);

void vnode_ref(vnode_t *vnode);

void vnode_deref(vnode_t *vnode);

static inline vnode_type_t mode_to_type(uint32_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR: return VNODE_DIRECTORY;
    case S_IFLNK: return VNODE_SYMLINK;
    case S_IFREG: return VNODE_REGULAR;
    case S_IFCHR: return VNODE_CHAR_DEV;
    case S_IFBLK: return VNODE_BLOCK_DEV;
    case S_IFIFO: return VNODE_FIFO;
    case S_IFSOCK: return VNODE_SOCKET;
    default: return VNODE_UNKNOWN;
    }
}

static inline unsigned char type_to_dirent_kind(vnode_type_t type) {
    switch (type) {
    case VNODE_UNKNOWN: return DT_UNKNOWN;
    case VNODE_DIRECTORY: return DT_DIR;
    case VNODE_SYMLINK: return DT_LNK;
    case VNODE_REGULAR: return DT_REG;
    case VNODE_CHAR_DEV: return DT_CHR;
    case VNODE_BLOCK_DEV: return DT_BLK;
    case VNODE_FIFO: return DT_FIFO;
    case VNODE_SOCKET: return DT_SOCK;
    }
}

#endif // HYDROGEN_FS_VFS_H
