#include "sched/proc.h"
#include "asm/irq.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "proxima/compiler.h"
#include "sched/mutex.h"
#include "sched/sched.h"
#include "string.h"
#include "util/idmap.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <limits.h>

proc_t kernel_proc = {.references = 1};

static idmap_t proc_map;
static mutex_t proc_map_lock;

void init_proc(void) {
    int id = idmap_alloc(&proc_map, &kernel_proc);
    if (id < 0) panic("failed to allocate id for kernel process (%d)", id);
    ASSERT(id == 0);

    ident_t *ident = vmalloc(sizeof(*ident));
    if (!ident) panic("failed to allocate identity for kernel process");
    memset(ident, 0, sizeof(*ident));
    ident->references = 1;
    kernel_proc.identity = ident;
}

void proc_ref(proc_t *proc) {
    __atomic_fetch_add(&proc->references, 1, __ATOMIC_ACQUIRE);
}

void proc_deref(proc_t *proc) {
    while (__atomic_fetch_sub(&proc->references, 1, __ATOMIC_ACQ_REL) == 1) {
        proc_t *parent = proc->parent;

        mutex_lock(&proc_map_lock);
        idmap_free(&proc_map, proc->id);
        mutex_unlock(&proc_map_lock);

        vmfree(proc, sizeof(*proc));
        proc = parent;
    }
}

void proc_make_zombie(proc_t *proc) {
    ident_deref(proc->identity);
    vnode_deref(proc->root);
    vmm_deref(proc->vmm);

    proc->identity = NULL;
    proc->root = NULL;
    proc->vmm = NULL;

    for (long i = 0; i < proc->fd_capacity; i++) {
        if (proc->fds[i].file) {
            file_deref(proc->fds[i].file);
        }
    }

    vmfree(proc->fds, proc->fd_capacity * sizeof(*proc->fds));
    proc->fds = NULL;
    proc->fd_capacity = 0;
    proc->fd_search_min = 0;

    mutex_lock(&proc_map_lock);
    UNUSED void *old = idmap_free(&proc_map, proc->id);
    ASSERT(proc == old);
    mutex_unlock(&proc_map_lock);

    task_t *cur = node_to_obj(task_t, priv_node, proc->waiting_tasks.first);
    while (cur != NULL) {
        task_t *next = node_to_obj(task_t, priv_node, cur->priv_node.next);
        sched_start(cur);
        cur = next;
    }

    list_clear(&proc->waiting_tasks);
}

int create_thread(task_t **out, task_func_t func, void *ctx, cpu_t *cpu) {
    task_t *task;
    int error = sched_create(&task, func, ctx, cpu);
    if (error) return error;

    proc_ref(current_proc);
    task->process = current_proc;

    irq_state_t state = spin_lock(&current_proc->lock);
    list_insert_tail(&current_proc->tasks, &task->proc_node);
    spin_unlock(&current_proc->lock, state);

    sched_start(task);
    *out = task;
    return 0;
}

int create_process(proc_t **out, task_func_t func, void *ctx, vmm_t *vmm) {
    proc_t *proc = vmalloc(sizeof(*proc));
    if (!proc) return ERR_OUT_OF_MEMORY;

    task_t *task;
    int error = sched_create(&task, func, ctx, NULL);
    if (error) {
        vmfree(proc, sizeof(*proc));
        return error;
    }

    mutex_lock(&proc_map_lock);
    int id = idmap_alloc(&proc_map, proc);
    mutex_unlock(&proc_map_lock);

    if (id < 0) {
        task_deref(task);
        vmfree(proc, sizeof(*proc));
        return -id;
    }

    memset(proc, 0, sizeof(*proc));
    proc->references = 2;
    proc->parent = current_proc;
    proc->id = id;
    proc->identity = get_identity();
    proc->root = get_root();
    proc->umask = __atomic_load_n(&proc->umask, __ATOMIC_ACQUIRE);

    if (vmm) proc->vmm = vmm;
    else proc->vmm = current_proc->vmm;

    if (proc->vmm) vmm_ref(proc->vmm);

    proc_ref(current_proc); // for proc->parent

    task->process = proc;
    list_insert_tail(&proc->tasks, &task->proc_node);

    sched_start(task);
    *out = proc;
    return 0;
}

bool proc_wait(proc_t *proc, uint64_t timeout) {
    irq_state_t state = spin_lock(&proc->lock);

    bool success = list_is_empty(&proc->tasks);

    if (!success) {
        list_insert_tail(&proc->waiting_tasks, &current_task->priv_node);
        success = sched_stop(timeout, &proc->lock);
        if (!success) list_remove(&proc->waiting_tasks, &current_task->priv_node);
    }

    spin_unlock(&proc->lock, state);
    return success;
}

ident_t *get_identity(void) {
    irq_state_t state = spin_lock(&current_proc->lock);
    ident_t *ident = current_proc->identity;
    ident->references += 1;
    spin_unlock(&current_proc->lock, state);
    return ident;
}

void ident_ref(ident_t *ident) {
    __atomic_fetch_add(&ident->references, 1, __ATOMIC_ACQUIRE);
}

void ident_deref(ident_t *ident) {
    if (__atomic_fetch_sub(&ident->references, 1, __ATOMIC_ACQ_REL) == 1) {
        vmfree(ident, sizeof(*ident));
    }
}

void set_identity(ident_t *identity) {
    ident_ref(identity);

    irq_state_t state = spin_lock(&current_proc->lock);
    ident_t *old = current_proc->identity;
    current_proc->identity = identity;
    spin_unlock(&current_proc->lock, state);

    ident_deref(old);
}

ident_t *clone_identity(void) {
    ident_t *ident = vmalloc(sizeof(*ident));
    if (!ident) return NULL;
    ident_t *old = get_identity();
    memcpy(ident, old, sizeof(*ident));
    ident_deref(old);
    return ident;
}

vnode_t *get_root(void) {
    irq_state_t state = spin_lock(&current_proc->lock);
    vnode_t *root = current_proc->root;
    vnode_ref(root);
    spin_unlock(&current_proc->lock, state);

    return root;
}

void set_root(vnode_t *vnode) {
    vnode_ref(vnode);

    irq_state_t state = spin_lock(&current_proc->lock);
    vnode_t *old = current_proc->root;
    current_proc->root = vnode;
    spin_unlock(&current_proc->lock, state);

    if (old) vnode_deref(old);
}

file_t *get_file_description(proc_t *proc, int fd, bool locked) {
    if (fd < 0) return NULL;

    if (!locked) mutex_lock(&proc->fds_lock);

    file_t *file = fd < proc->fd_capacity ? proc->fds[fd].file : NULL;
    if (file) file_ref(file);

    if (!locked) mutex_unlock(&proc->fds_lock);
    return file;
}

int get_free_fd(proc_t *proc, int min) {
    if (min < proc->fd_search_min) min = proc->fd_search_min;

    while (min < proc->fd_capacity) {
        if (proc->fds[min].file == NULL) break;
        min += 1;
    }

    return min;
}

int assign_fd(proc_t *proc, int fd, file_t *description, int flags) {
    if (fd == INT_MAX) return ERR_NO_MORE_HANDLES;

    long cap = proc->fd_capacity;
    while (cap <= fd) {
        if (cap != 0) cap += cap / 2;
        else cap = 8;
    }

    if (cap != proc->fd_capacity) {
        size_t old_size = proc->fd_capacity * sizeof(*proc->fds);
        size_t new_size = cap * sizeof(*proc->fds);

        file_descriptor_t *buf = vmrealloc(proc->fds, old_size, new_size);
        if (!buf) return ERR_OUT_OF_MEMORY;
        memset(buf + old_size, 0, new_size - old_size);

        proc->fds = buf;
        proc->fd_capacity = cap;
    }

    ASSERT(proc->fds[fd].file == NULL);

    proc->fds[fd].file = description;
    proc->fds[fd].flags = flags;
    file_ref(description);

    if (fd == proc->fd_search_min) proc->fd_search_min += 1;
    return 0;
}

file_t *remove_fd(proc_t *proc, int fd) {
    if (fd >= proc->fd_capacity) return NULL;

    file_t *file = proc->fds[fd].file;
    proc->fds[fd].file = NULL;
    if (fd < proc->fd_search_min) proc->fd_search_min = fd;

    return file;
}

int alloc_fd(file_t *description, int flags) {
    mutex_lock(&current_proc->fds_lock);

    int fd = get_free_fd(current_proc, 0);
    int error = assign_fd(current_proc, fd, description, flags);

    mutex_unlock(&current_proc->fds_lock);
    return error == 0 ? fd : -error;
}
