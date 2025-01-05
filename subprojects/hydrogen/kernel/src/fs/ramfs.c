#include "fs/ramfs.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "hydrogen/dirent.h"
#include "hydrogen/error.h"
#include "hydrogen/stat.h"
#include "hydrogen/vfs.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/time.h"
#include "util/xarray.h"
#include <stdint.h>

typedef struct ramfs_dirent ramfs_dirent_t;
typedef struct ramfs_vnode ramfs_vnode_t;

typedef struct {
    vfs_t base;
    uint64_t next_id;
} ramfs_t;

struct ramfs_dirent {
    size_t references;
    ramfs_vnode_t *directory;
    ramfs_dirent_t *prev;
    ramfs_dirent_t *next;

    list_node_t iter_node;
    uint64_t id;

    void *name;
    size_t length;
    uint64_t hash;

    ramfs_vnode_t *vnode;
};

struct ramfs_vnode {
    vnode_t base;
    uint64_t links;
    uint64_t size;
    uint64_t blocks;
    int64_t atime;
    int64_t btime;
    int64_t ctime;
    int64_t mtime;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;

    union {
        struct {
            ramfs_vnode_t *parent;
            ramfs_dirent_t **children;
            size_t capacity;
            size_t count;

            list_t iter_list;
            uint64_t next_id;
        } dir;
        struct {
            void *target;
        } link;
        struct {
            xarray_t pages;
            vm_object_t obj;
        } reg;
    };
};

static void free_page_callback(void *ptr, void *ctx) {
    page_t *page = virt_to_page(ptr);
    if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
        free_page_now(page);
    }

    ((ramfs_vnode_t *)ctx)->blocks -= 1;
}

static void ramfs_vnode_free(vnode_t *ptr) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    switch (self->base.type) {
    case VNODE_DIRECTORY:
        ASSERT(self->dir.count == 0);
        ASSERT(list_is_empty(&self->dir.iter_list));
        vmfree(self->dir.children, sizeof(ramfs_dirent_t *) * self->dir.capacity);
        break;
    case VNODE_SYMLINK: vmfree(self->link.target, self->size); break;
    case VNODE_REGULAR: xarray_clear(&self->reg.pages, free_page_callback, self); break;
    default: break;
    }

    vmfree(self, sizeof(*self));
}

static bool ramfs_vnode_access(vnode_t *ptr, uint32_t mask, ident_t *ident) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    if (ident->uid == self->uid) mask <<= 6;
    else if (ident->gid == self->gid) mask <<= 3;

    return (self->mode & mask) == mask;
}

static int ramfs_vnode_stat(vnode_t *ptr, hydrogen_stat_t *out) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    out->links = self->links;
    out->size = self->size;
    out->blocks = self->blocks;
    out->block_size = PAGE_SIZE;
    out->atime = self->atime;
    out->btime = self->btime;
    out->ctime = self->ctime;
    out->mtime = self->mtime;
    out->mode = self->mode;
    out->uid = self->uid;
    out->gid = self->gid;

    return 0;
}

static int ramfs_vnode_utimes(vnode_t *ptr, int64_t atime, int64_t mtime, ident_t *ident) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    int64_t cur = get_timestamp();

    if (self->uid != ident->uid) {
        if ((atime != INT64_MIN && atime != INT64_MAX) || (mtime != INT64_MIN && mtime != INT64_MAX) ||
            !ramfs_vnode_access(ptr, S_IWOTH, ident)) {
            return ERR_ACCESS_DENIED;
        }
    }

    if (atime == INT64_MAX) atime = cur;
    if (mtime == INT64_MAX) mtime = cur;

    if (atime != INT64_MIN) self->atime = atime;
    if (mtime != INT64_MIN) self->mtime = mtime;

    self->ctime = cur;

    return 0;
}

static int ramfs_vnode_chown(vnode_t *ptr, uint32_t uid, uint32_t gid, ident_t *ident) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    if (ident->uid != 0 && ident->uid != self->uid) return ERR_ACCESS_DENIED;

    if (uid != UINT32_MAX) self->uid = uid;
    if (gid != UINT32_MAX) self->gid = gid;

    self->ctime = get_timestamp();

    return 0;
}

static int ramfs_vnode_chmod(vnode_t *ptr, uint32_t mode, ident_t *ident) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    if (ident->uid != 0 && ident->uid != self->uid) return ERR_ACCESS_DENIED;

    self->mode = (self->mode & S_IFMT) | mode;
    self->ctime = get_timestamp();

    return 0;
}

static const vnode_ops_t ramfs_vnode_unknown_ops = {
        .free = ramfs_vnode_free,
        .access = ramfs_vnode_access,
        .stat = ramfs_vnode_stat,
        .utimes = ramfs_vnode_utimes,
        .chown = ramfs_vnode_chown,
        .chmod = ramfs_vnode_chmod,
};
static const vnode_ops_t ramfs_vnode_dir_ops;

static int ramfs_vnode_link_read(vnode_t *ptr, const void **target, size_t *target_len) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    *target = self->link.target;
    *target_len = self->size;
    self->atime = get_timestamp();
    return 0;
}

static const vnode_ops_t ramfs_vnode_link_ops = {
        .free = ramfs_vnode_free,
        .access = ramfs_vnode_access,
        .stat = ramfs_vnode_stat,
        .utimes = ramfs_vnode_utimes,
        .chown = ramfs_vnode_chown,
        .chmod = ramfs_vnode_chmod,
        .link.read = ramfs_vnode_link_read,
};

static int ramfs_vnode_reg_truncate(vnode_t *ptr, uint64_t size) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    xarray_trunc(&self->reg.pages, (size + PAGE_MASK) >> PAGE_SHIFT, free_page_callback, self);
    self->size = size;
    self->reg.obj.size = (size + PAGE_MASK) & ~PAGE_MASK;

    self->ctime = get_timestamp();
    self->mtime = self->ctime;

    return 0;
}

static int ramfs_vnode_reg_get_size(vnode_t *ptr, uint64_t *out) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    *out = self->size;
    return 0;
}

// you must own self->base.lock
static page_t *get_page_for_writing(ramfs_vnode_t *self, size_t index) {
    page_t *page = xarray_get(&self->reg.pages, index);

    if (page == NULL) {
        page = alloc_page_now();
        if (unlikely(!page)) return NULL;

        page->anon.references = 1;
        page->anon.autounreserve = true;

        memset(page_to_virt(page), 0, PAGE_SIZE);
        xarray_put(&self->reg.pages, index, page);
        self->blocks += 1;
    }

    return page;
}

static int ramfs_vnode_reg_read(vnode_t *ptr, void *buffer, size_t *size, uint64_t position) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    size_t remaining = *size;
    size_t total = 0;

    while (remaining > 0 && position < self->size) {
        size_t index = position >> PAGE_SHIFT;
        size_t offset = position & PAGE_MASK;
        size_t cur = PAGE_SIZE - offset;
        size_t avail = self->size - position;
        if (cur > avail) cur = avail;
        if (cur > remaining) cur = remaining;

        page_t *page = xarray_get(&self->reg.pages, index);

        int error;
        if (page) {
            error = memcpy_user(buffer, page_to_virt(page) + offset, cur);
        } else {
            error = memset_user(buffer, 0, cur);
        }

        if (unlikely(error)) {
            if (total != 0) break;
            return error;
        }

        buffer += cur;
        remaining -= cur;
        total += cur;
        position += cur;
    }

    if (total != 0) self->atime = get_timestamp();

    *size = total;
    return 0;
}

static int ramfs_vnode_reg_write(vnode_t *ptr, const void *buffer, size_t *size, uint64_t position) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    size_t remaining = *size;
    size_t total = 0;
    int error = 0;

    while (remaining > 0) {
        size_t index = position >> PAGE_SHIFT;
        size_t offset = position & PAGE_MASK;
        size_t max = PAGE_SIZE - offset;
        size_t cur = max < remaining ? max : remaining;

        page_t *page = get_page_for_writing(self, index);
        if (unlikely(!page)) {
            error = ERR_DISK_FULL;
            break;
        }

        error = memcpy_user(page_to_virt(page) + offset, buffer, cur);
        if (unlikely(error)) break;

        buffer += cur;
        remaining -= cur;
        total += cur;
        position += cur;
    }

    if (likely(error == 0 || total != 0)) {
        if (position > self->size) {
            self->size = position;
            self->reg.obj.size = (position + PAGE_MASK) & ~PAGE_MASK;
        }

        self->ctime = get_timestamp();
        self->mtime = self->ctime;
        error = 0;
    }

    *size = total;
    return error;
}

static int ramfs_vnode_reg_mmap(vnode_t *ptr, uintptr_t *addr, size_t size, int flags, size_t offset) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    bool first = __atomic_load_n(&self->reg.obj.references, __ATOMIC_ACQUIRE) == 0;

    int error = vmm_add(addr, size, flags, &self->reg.obj, offset);
    if (unlikely(error)) return error;

    // technically this is the wrong moment to do this, but whatever
    self->atime = get_timestamp();
    if (flags & VMM_WRITE) {
        self->ctime = self->atime;
        self->mtime = self->atime;
    }

    if (first) vnode_ref(ptr);
    return 0;
}

static const vnode_ops_t ramfs_vnode_reg_ops = {
        .free = ramfs_vnode_free,
        .access = ramfs_vnode_access,
        .stat = ramfs_vnode_stat,
        .utimes = ramfs_vnode_utimes,
        .chown = ramfs_vnode_chown,
        .chmod = ramfs_vnode_chmod,
        .reg.truncate = ramfs_vnode_reg_truncate,
        .reg.get_size = ramfs_vnode_reg_get_size,
        .reg.read = ramfs_vnode_reg_read,
        .reg.write = ramfs_vnode_reg_write,
        .reg.mmap = ramfs_vnode_reg_mmap,
};

static void ramfs_file_object_free(vm_object_t *self) {
    ramfs_vnode_t *vnode = node_to_obj(ramfs_vnode_t, reg.obj, self);
    vnode_deref(&vnode->base);
}

static bool ramfs_file_object_allow_flags(UNUSED vm_object_t *self, UNUSED int flags) {
    return true;
}

static uint64_t ramfs_file_object_get_base_pte(vm_object_t *self, vm_region_t *region, size_t offset) {
    ramfs_vnode_t *vnode = node_to_obj(ramfs_vnode_t, reg.obj, self);
    mutex_lock(&vnode->base.lock);

    if (unlikely(offset >= self->size)) {
        mutex_unlock(&vnode->base.lock);
        return 0;
    }

    page_t *page = get_page_for_writing(vnode, offset >> PAGE_SHIFT);
    if (unlikely(!page)) panic("TODO: mmap holes that cannot be filled");
    __atomic_fetch_add(&page->anon.references, 1, __ATOMIC_ACQ_REL);

    mutex_unlock(&vnode->base.lock);

    uint64_t pte = page_to_phys(page) | PTE_ANON;
    if (region->flags & VMM_PRIVATE) pte |= PTE_COW;
    return pte;
}

static const vm_object_ops_t ramfs_file_object_ops = {
        .free = ramfs_file_object_free,
        .allow_flags = ramfs_file_object_allow_flags,
        .get_base_pte = ramfs_file_object_get_base_pte,
};

static ramfs_vnode_t *create_vnode(ramfs_t *fs, ramfs_vnode_t *dir, uint32_t mode, ident_t *ident) {
    ramfs_vnode_t *vnode = vmalloc(sizeof(*vnode));
    if (unlikely(!vnode)) return NULL;
    memset(vnode, 0, sizeof(*vnode));

    vnode->base.references = 1;
    vnode->base.vfs = &fs->base;
    vnode->base.type = mode_to_type(mode);
    vnode->links = 1;
    vnode->atime = get_timestamp();
    vnode->btime = vnode->atime;
    vnode->ctime = vnode->atime;
    vnode->mtime = vnode->atime;
    vnode->uid = ident->uid;
    vnode->gid = ident->gid;
    vnode->mode = mode;

    ASSERT(vnode->base.type != VNODE_UNKNOWN);

    if (dir != NULL && (dir->mode & S_ISGID) != 0) {
        vnode->gid = dir->gid;
        if (S_ISDIR(mode)) vnode->mode |= S_ISGID;
    }

    switch (vnode->base.type) {
    case VNODE_DIRECTORY:
        vnode->base.ops = &ramfs_vnode_dir_ops;
        vnode->links += 1; // due to the . entry

        vnode->dir.capacity = 16;
        vnode->dir.children = vmalloc(sizeof(ramfs_dirent_t *) * vnode->dir.capacity);
        if (unlikely(!vnode->dir.children)) {
            vmfree(vnode, sizeof(*vnode));
        }
        memset(vnode->dir.children, 0, sizeof(ramfs_dirent_t *) * vnode->dir.capacity);

        vnode->dir.parent = dir;
        vnode->dir.next_id = 2;
        break;
    case VNODE_SYMLINK: vnode->base.ops = &ramfs_vnode_link_ops; break;
    case VNODE_REGULAR:
        vnode->base.ops = &ramfs_vnode_reg_ops;
        vnode->reg.obj.ops = &ramfs_file_object_ops;
        break;
    default: vnode->base.ops = &ramfs_vnode_unknown_ops; break;
    }

    vnode->base.id = __atomic_fetch_add(&fs->next_id, 1, __ATOMIC_RELAXED);
    return vnode;
}

static void ramfs_dirent_ref(ramfs_dirent_t *entry) {
    entry->references += 1;
}

static void ramfs_dirent_deref(ramfs_dirent_t *entry) {
    if (--entry->references == 0) {
        ASSERT(entry->vnode == NULL);

        list_remove(&entry->directory->dir.iter_list, &entry->iter_node);
        vmfree(entry->name, entry->length);
        vmfree(entry, sizeof(*entry));
    }
}

typedef struct {
    file_t base;
    uint64_t head_state; // 0: next is ., 1: next is .., 2: next is determined by prev
    ramfs_dirent_t *prev;
} ramfs_open_dir_t;

static void ramfs_open_dir_free(file_t *ptr) {
    ramfs_open_dir_t *self = (ramfs_open_dir_t *)ptr;

    if (self->prev) {
        ramfs_vnode_t *vnode = (ramfs_vnode_t *)self->base.vnode;
        mutex_lock(&vnode->base.lock);
        ramfs_dirent_deref(self->prev);
        mutex_unlock(&vnode->base.lock);
    }

    vmfree(self, sizeof(*self));
}

static ramfs_dirent_t *next_dirent(ramfs_vnode_t *vnode, ramfs_dirent_t *prev) {
    return node_to_obj(ramfs_dirent_t, iter_node, prev ? prev->iter_node.next : vnode->dir.iter_list.first);
}

static int emit_dirent(
        void *buffer,
        size_t rem,
        const void *name,
        size_t length,
        vnode_t *vnode,
        uint64_t pos,
        size_t *len
) {
    *len = 0;

    size_t needed_length = offsetof(hydrogen_dirent_t, name) + length;
    needed_length = (needed_length + (_Alignof(hydrogen_dirent_t) - 1)) & ~(_Alignof(hydrogen_dirent_t) - 1);
    if (needed_length > rem) return 0;

    hydrogen_dirent_t entry = {.id = vnode->id, .pos = pos, .length = length, .kind = type_to_dirent_kind(vnode->type)};

    int error = memcpy_user(buffer, &entry, offsetof(hydrogen_dirent_t, name));
    if (unlikely(error)) return error;

    error = memcpy_user(buffer + offsetof(hydrogen_dirent_t, name), name, length);
    if (unlikely(error)) return error;

    return 0;
}

// you must own dir->base.lock
static int get_parent_vnode(ramfs_vnode_t *dir, vnode_t **out) {
    if (dir->dir.parent) {
        *out = &dir->dir.parent->base;
        vnode_ref(*out);
        return 0;
    }

    ASSERT(&dir->base == dir->base.vfs->root);
    return get_mountpoint_parent(dir->base.vfs, out);
}

// you must own dir->base.lock
static int emit_single(ramfs_open_dir_t *self, ramfs_vnode_t *dir, void **buffer, size_t *rem, size_t *tot, bool *eof) {
    ramfs_dirent_t *entry = next_dirent(dir, self->prev);

    while (entry != NULL && entry->vnode == NULL) {
        if (self->prev) ramfs_dirent_deref(self->prev);
        self->prev = entry;
        ramfs_dirent_ref(entry);
        entry = next_dirent(dir, entry);
    }

    size_t len;

    if (self->head_state < 2) {
        vnode_t *vnode;
        if (self->head_state == 0) {
            vnode = &dir->base;
            vnode_ref(vnode);
        } else {
            int error = get_parent_vnode(dir, &vnode);
            if (unlikely(error)) return error;
        }

        int error = emit_dirent(*buffer, *rem, "..", self->head_state + 1, vnode, self->head_state, &len);
        vnode_deref(vnode);
        if (unlikely(error)) return error;

        if (len != 0) self->head_state += 1;
    } else if (entry != NULL) {
        int error = emit_dirent(*buffer, *rem, entry->name, entry->length, &entry->vnode->base, entry->id, &len);
        if (unlikely(error)) return error;

        if (len != 0) {
            if (self->prev) ramfs_dirent_deref(self->prev);
            self->prev = entry;
            ramfs_dirent_ref(entry);
        }
    } else {
        len = 0;
    }

    *buffer += len;
    *rem -= len;
    *tot += len;
    *eof = self->head_state == 2 && entry == NULL;
    return 0;
}

static int ramfs_open_dir_read(file_t *ptr, void *buffer, size_t *size) {
    ramfs_open_dir_t *self = (ramfs_open_dir_t *)ptr;
    ramfs_vnode_t *vnode = (ramfs_vnode_t *)ptr->vnode;

    mutex_lock(&vnode->base.lock);

    bool eof;
    int error;
    size_t tot = 0;

    do {
        error = emit_single(self, vnode, &buffer, size, &tot, &eof);
        if (unlikely(error)) {
            mutex_unlock(&vnode->base.lock);
            return error;
        }
    } while (!eof);

    if (tot != 0) vnode->atime = get_timestamp();

    mutex_unlock(&vnode->base.lock);

    *size = tot;
    return tot != 0 || eof ? 0 : ERR_OVERFLOW;
}

static int ramfs_open_dir_seek(file_t *ptr, uint64_t *offset, hydrogen_whence_t whence) {
    ramfs_open_dir_t *self = (ramfs_open_dir_t *)ptr;
    ramfs_vnode_t *vnode = (ramfs_vnode_t *)self->base.vnode;

    mutex_lock(&vnode->base.lock);

    uint64_t new_pos = *offset;
    switch (whence) {
    case HYDROGEN_WHENCE_SET: break;
    case HYDROGEN_WHENCE_CUR:
        if (self->head_state < 2) {
            new_pos += self->head_state;
        } else if (self->prev) {
            new_pos += self->prev->id + 1;
        } else {
            new_pos += 2;
        }
        break;
    case HYDROGEN_WHENCE_END: {
        ramfs_dirent_t *last = node_to_obj(ramfs_dirent_t, iter_node, vnode->dir.iter_list.last);
        if (last) {
            new_pos += last->id + 1;
        } else {
            new_pos += 2;
        }
        break;
    }
    }

    if (new_pos <= 2) {
        if (self->prev) ramfs_dirent_deref(self->prev);
        self->prev = NULL;
        self->head_state = new_pos;
    } else {
        self->head_state = 2;

        while (self->prev && (self->prev->id >= new_pos || self->prev->vnode == NULL)) {
            ramfs_dirent_t *nprev = node_to_obj(ramfs_dirent_t, iter_node, self->prev->iter_node.prev);
            ramfs_dirent_deref(self->prev);
            ramfs_dirent_ref(nprev);
            self->prev = nprev;
        }

        ramfs_dirent_t *next = next_dirent(vnode, self->prev);

        while (next != NULL && (next->id < new_pos || next->vnode == NULL)) {
            if (self->prev) ramfs_dirent_deref(self->prev);
            ramfs_dirent_ref(next);
            self->prev = next;
            next = next_dirent(vnode, next);
        }

        new_pos = self->prev ? self->prev->id + 1 : self->head_state;
    }

    mutex_unlock(&vnode->base.lock);
    *offset = new_pos;
    return 0;
}

static const file_ops_t ramfs_open_dir_ops = {
        .free = ramfs_open_dir_free,
        .read = ramfs_open_dir_read,
        .seek = ramfs_open_dir_seek,
};

static int ramfs_vnode_dir_open(UNUSED vnode_t *ptr, file_t **out) {
    ramfs_open_dir_t *handle = vmalloc(sizeof(*handle));
    if (unlikely(!handle)) return ERR_OUT_OF_MEMORY;
    memset(handle, 0, sizeof(*handle));

    handle->base.ops = &ramfs_open_dir_ops;
    handle->base.references = 1;

    *out = &handle->base;
    return 0;
}

// FNV-1a
static uint64_t make_hash(const unsigned char *name, size_t length) {
    uint64_t hash = 0xcbf29ce484222325;

    for (size_t i = 0; i < length; i++) {
        hash ^= name[i];
        hash *= 0x00000100000001b3;
    }

    return hash;
}

static ramfs_dirent_t *do_lookup(ramfs_vnode_t *dir, const void *name, size_t length, uint64_t hash) {
    size_t bucket = hash & (dir->dir.capacity - 1);
    ramfs_dirent_t *cur = dir->dir.children[bucket];

    while (cur != NULL && (cur->hash != hash || cur->length != length || memcmp(cur->name, name, length))) {
        cur = cur->next;
    }

    return cur;
}

static void maybe_expand(ramfs_vnode_t *dir) {
    size_t cap = dir->dir.capacity;
    while (dir->dir.count >= (cap - (cap / 4))) {
        cap *= 2;
    }

    if (cap <= dir->dir.capacity) return;

    ramfs_dirent_t **new_table = vmalloc(sizeof(ramfs_dirent_t *) * cap);
    if (unlikely(!new_table)) return;
    memset(new_table, 0, sizeof(ramfs_dirent_t *) * cap);

    for (size_t i = 0; i < dir->dir.capacity; i++) {
        ramfs_dirent_t *cur = dir->dir.children[i];

        while (cur != NULL) {
            ramfs_dirent_t *next = cur->next;

            size_t bucket = cur->hash & (cap - 1);
            cur->prev = NULL;
            cur->next = new_table[bucket];
            if (cur->next) cur->next->prev = cur;
            new_table[bucket] = cur;

            cur = next;
        }
    }

    vmfree(dir->dir.children, sizeof(ramfs_dirent_t *) * dir->dir.capacity);
    dir->dir.children = new_table;
    dir->dir.capacity = cap;
}

static int ramfs_vnode_dir_lookup(vnode_t *ptr, vnode_t **out, const void *name, size_t length) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;

    const char *n = name;
    if (length == 2 && n[0] == '.' && n[1] == '.') {
        *out = self->dir.parent ? &self->dir.parent->base : &self->base;
        vnode_ref(*out);
        return 0;
    }

    ramfs_dirent_t *entry = do_lookup(self, name, length, make_hash(name, length));

    if (entry) {
        *out = &entry->vnode->base;
        vnode_ref(*out);
        return 0;
    } else {
        return ERR_NOT_FOUND;
    }
}

static int do_add(
        ramfs_vnode_t *dir,
        const void *name,
        size_t length,
        uint64_t hash,
        ramfs_vnode_t *vnode,
        int64_t timestamp
) {
    ASSERT(dir->links >= 2);

    ramfs_dirent_t *entry = vmalloc(sizeof(*entry));
    if (unlikely(!entry)) return ERR_DISK_FULL;

    void *name_buf = vmalloc(length);
    if (unlikely(!name_buf)) {
        vmfree(entry, sizeof(*entry));
        return ERR_DISK_FULL;
    }

    memset(entry, 0, sizeof(*entry));
    memcpy(name_buf, name, length);

    entry->references = 1;
    entry->directory = dir;
    entry->prev = NULL;
    entry->name = name_buf;
    entry->length = length;
    entry->hash = hash;
    entry->vnode = vnode;

    maybe_expand(dir);

    size_t bucket = hash & (dir->dir.capacity - 1);
    entry->next = dir->dir.children[bucket];
    if (entry->next) entry->next->prev = entry;
    dir->dir.children[bucket] = entry;

    dir->dir.count += 1;

    entry->id = dir->dir.next_id++;
    list_insert_tail(&dir->dir.iter_list, &entry->iter_node);

    dir->ctime = timestamp;
    dir->mtime = timestamp;
    if (vnode->base.type == VNODE_DIRECTORY) dir->links += 1;

    vnode_ref(&vnode->base);
    return 0;
}

static int ramfs_vnode_dir_mknod(
        vnode_t *ptr,
        vnode_t **out,
        const void *name,
        size_t length,
        uint32_t mode,
        ident_t *ident
) {
    ASSERT(!S_ISLNK(mode));

    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    if (self->links == 0) return ERR_NOT_FOUND;

    uint64_t hash = make_hash(name, length);
    ramfs_dirent_t *entry = do_lookup(self, name, length, hash);
    if (entry != NULL) {
        *out = &entry->vnode->base;
        vnode_ref(*out);
        return ERR_ALREADY_EXISTS;
    }

    ramfs_vnode_t *vnode = create_vnode((ramfs_t *)self->base.vfs, self, mode, ident);
    if (unlikely(!vnode)) return ERR_DISK_FULL;

    int error = do_add(self, name, length, hash, vnode, vnode->btime);
    if (likely(error == 0)) *out = &vnode->base;
    else vnode_deref(&vnode->base);
    return error;
}

static int ramfs_vnode_dir_symlink(
        vnode_t *ptr,
        const void *name,
        size_t length,
        const void *target_name,
        size_t target_len,
        ident_t *ident
) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    if (self->links == 0) return ERR_NOT_FOUND;

    uint64_t hash = make_hash(name, length);
    ramfs_dirent_t *entry = do_lookup(self, name, length, hash);
    if (entry != NULL) return ERR_ALREADY_EXISTS;

    ramfs_vnode_t *vnode = create_vnode((ramfs_t *)self->base.vfs, self, S_IFLNK | S_IRWXUGO, ident);
    if (unlikely(!vnode)) return ERR_DISK_FULL;

    void *buf = vmalloc(target_len);
    if (unlikely(!buf)) {
        vnode_deref(&vnode->base);
        return ERR_DISK_FULL;
    }
    memcpy(buf, target_name, target_len);
    vnode->size = target_len;
    vnode->link.target = buf;

    int error = do_add(self, name, length, hash, vnode, vnode->btime);
    if (unlikely(error)) vnode_deref(&vnode->base);
    return error;
}

static int ramfs_vnode_dir_link(vnode_t *ptr, const void *name, size_t length, vnode_t *target_ptr) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    if (self->links == 0) return ERR_NOT_FOUND;

    ramfs_vnode_t *target = (ramfs_vnode_t *)target_ptr;
    if (target->base.type == VNODE_DIRECTORY) return ERR_IS_A_DIRECTORY;

    uint64_t hash = make_hash(name, length);
    ramfs_dirent_t *entry = do_lookup(self, name, length, hash);
    if (entry != NULL) return ERR_ALREADY_EXISTS;

    mutex_lock(&target->base.lock);

    int64_t timestamp = get_timestamp();
    int error = do_add(self, name, length, hash, target, timestamp);
    if (unlikely(error)) return error;

    target->links += 1;
    target->ctime = timestamp;

    mutex_unlock(&target->base.lock);
    return 0;
}

static void remove_entry(ramfs_vnode_t *vnode, ramfs_dirent_t *entry) {
    if (entry->prev) entry->prev->next = entry->next;
    else vnode->dir.children[entry->hash & (vnode->dir.capacity - 1)] = entry->next;

    if (entry->next) entry->next->prev = entry->prev;

    vnode->dir.count -= 1;
    entry->vnode = NULL;
    ramfs_dirent_deref(entry);
}

static int ramfs_vnode_dir_unlink(vnode_t *ptr, const void *name, size_t length, ident_t *ident, bool dir) {
    ramfs_vnode_t *self = (ramfs_vnode_t *)ptr;
    if ((self->mode & S_ISVTX) != 0 && self->uid != ident->uid) return ERR_ACCESS_DENIED;

    uint64_t hash = make_hash(name, length);
    ramfs_dirent_t *entry = do_lookup(self, name, length, hash);
    if (unlikely(!entry)) return ERR_NOT_FOUND;

    ramfs_vnode_t *vnode = entry->vnode;
    if (vnode->base.type == VNODE_DIRECTORY) {
        if (!dir) return ERR_IS_A_DIRECTORY;
    } else if (dir) {
        return ERR_NOT_A_DIRECTORY;
    }

    mutex_lock(&vnode->base.lock);

    int64_t timestamp = get_timestamp();

    if (vnode->base.type == VNODE_DIRECTORY) {
        if (unlikely(vnode->dir.count != 0)) {
            mutex_unlock(&vnode->base.lock);
            return ERR_NOT_EMPTY;
        }

        vnode->links = 0;
        self->links -= 1; // due to the .. entry
    } else {
        vnode->links -= 1;
    }

    vnode->ctime = timestamp;
    self->ctime = timestamp;
    self->mtime = timestamp;

    mutex_unlock(&vnode->base.lock);
    vnode_deref(&vnode->base);

    remove_entry(self, entry);
    return 0;
}

static int ramfs_vnode_dir_rename(
        vnode_t *src_ptr,
        const void *src_name,
        size_t src_length,
        vnode_t *dest_ptr,
        const void *dest_name,
        size_t dest_length,
        ident_t *ident
) {
    ramfs_vnode_t *src = (ramfs_vnode_t *)src_ptr;
    if ((src->mode & S_ISVTX) != 0 && src->uid != ident->uid) return ERR_ACCESS_DENIED;

    ramfs_vnode_t *dest = (ramfs_vnode_t *)dest_ptr;

    // check if it's an ancestor directory
    for (ramfs_vnode_t *cur = dest->dir.parent; cur != NULL; cur = cur->dir.parent) {
        if (cur == src) return ERR_INVALID_ARGUMENT;
    }

    uint64_t src_hash = make_hash(src_name, src_length);
    ramfs_dirent_t *src_entry = do_lookup(src, src_name, src_length, src_hash);
    if (unlikely(!src_entry)) return ERR_NOT_FOUND;
    ramfs_vnode_t *src_vnode = src_entry->vnode;

    uint64_t dest_hash = make_hash(dest_name, dest_length);
    ramfs_dirent_t *dest_entry = do_lookup(dest, dest_name, dest_length, dest_hash);

    int64_t timestamp;

    if (dest_entry) {
        ramfs_vnode_t *dest_vnode = dest_entry->vnode;
        if (src_vnode == dest_vnode) return 0;

        mutex_lock(&src_vnode->base.lock);
        mutex_lock(&dest_vnode->base.lock);

        if (src_vnode->base.type == VNODE_DIRECTORY) {
            if (unlikely(dest_vnode->base.type != VNODE_DIRECTORY)) {
                mutex_unlock(&dest_vnode->base.lock);
                mutex_unlock(&src_vnode->base.lock);
                return ERR_NOT_A_DIRECTORY;
            }

            if (unlikely(dest_vnode->dir.count != 0)) {
                mutex_unlock(&dest_vnode->base.lock);
                mutex_unlock(&src_vnode->base.lock);
                return ERR_NOT_EMPTY;
            }

            dest_vnode->links = 0;
        } else if (dest_vnode->base.type == VNODE_DIRECTORY) {
            mutex_unlock(&dest_vnode->base.lock);
            mutex_unlock(&src_vnode->base.lock);
            return ERR_IS_A_DIRECTORY;
        } else {
            dest_vnode->links -= 1;
        }

        timestamp = get_timestamp();
        dest_vnode->ctime = timestamp;

        mutex_unlock(&dest_vnode->base.lock);
        mutex_unlock(&src_vnode->base.lock);
        vnode_deref(&dest_vnode->base);

        dest_entry->vnode = src_vnode;
    } else {
        timestamp = get_timestamp();
        int error = do_add(dest, dest_name, dest_length, dest_hash, src_vnode, timestamp);
        if (unlikely(error)) return error;
    }

    remove_entry(src, src_entry);

    src->ctime = timestamp;
    src->mtime = timestamp;
    dest->ctime = timestamp;
    dest->mtime = timestamp;

    return 0;
}

static const vnode_ops_t ramfs_vnode_dir_ops = {
        .free = ramfs_vnode_free,
        .access = ramfs_vnode_access,
        .stat = ramfs_vnode_stat,
        .utimes = ramfs_vnode_utimes,
        .chown = ramfs_vnode_chown,
        .chmod = ramfs_vnode_chmod,
        .dir.open = ramfs_vnode_dir_open,
        .dir.lookup = ramfs_vnode_dir_lookup,
        .dir.mknod = ramfs_vnode_dir_mknod,
        .dir.symlink = ramfs_vnode_dir_symlink,
        .dir.link = ramfs_vnode_dir_link,
        .dir.unlink = ramfs_vnode_dir_unlink,
        .dir.rename = ramfs_vnode_dir_rename,
};

int ramfs_create(vfs_t **out, uint32_t mode, ident_t *ident) {
    ramfs_t *fs = vmalloc(sizeof(*fs));
    if (unlikely(!fs)) return ERR_OUT_OF_MEMORY;
    memset(fs, 0, sizeof(*fs));

    ramfs_vnode_t *root = create_vnode(fs, NULL, S_IFDIR | mode, ident);
    if (unlikely(!root)) {
        vmfree(fs, sizeof(*fs));
        return ERR_OUT_OF_MEMORY;
    }
    fs->base.root = &root->base;

    fs->base.id = get_vfs_id();
    *out = &fs->base;
    return 0;
}
