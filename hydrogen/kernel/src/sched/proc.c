#include "sched/proc.h"
#include "asm/irq.h"
#include "hydrogen/error.h"
#include "mem/vheap.h"
#include "sched/mutex.h"
#include "sched/sched.h"
#include "string.h"
#include "util/idmap.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/spinlock.h"

proc_t kernel_proc = {.references = 1};

static idmap_t proc_map;
static mutex_t proc_map_lock;

void init_proc(void) {
    int id = idmap_alloc(&proc_map, &kernel_proc);
    if (id < 0) panic("failed to allocate id for kernel process (%d)", id);
    ASSERT(id == 0);

    identity_t *ident = vmalloc(sizeof(*ident));
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

int create_process(proc_t **out, task_func_t func, void *ctx) {
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

identity_t *get_identity(void) {
    spin_lock_noirq(&current_proc->lock);
    identity_t *ident = current_proc->identity;
    ident->references += 1;
    spin_unlock_noirq(&current_proc->lock);
    return ident;
}

void ident_ref(identity_t *ident) {
    __atomic_fetch_add(&ident->references, 1, __ATOMIC_ACQUIRE);
}

void ident_deref(identity_t *ident) {
    if (__atomic_fetch_sub(&ident->references, 1, __ATOMIC_ACQ_REL) == 1) {
        vmfree(ident, sizeof(*ident));
    }
}

void set_identity(identity_t *identity) {
    ident_ref(identity);

    spin_lock_noirq(&current_proc->lock);
    identity_t *old = current_proc->identity;
    current_proc->identity = identity;
    spin_unlock_noirq(&current_proc->lock);

    ident_deref(old);
}

identity_t *clone_identity(void) {
    identity_t *ident = vmalloc(sizeof(*ident));
    if (!ident) return NULL;
    identity_t *old = get_identity();
    memcpy(ident, old, sizeof(*ident));
    ident_deref(old);
    return ident;
}
