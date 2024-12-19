#include "sched/proc.h"
#include "asm/irq.h"
#include "errno.h"
#include "mem/heap.h"
#include "sched/mutex.h"
#include "sched/sched.h"
#include "string.h"
#include "util/idmap.h"
#include "util/list.h"
#include "util/panic.h"

proc_t kernel_proc = {.references = 1};

static idmap_t proc_map;
static mutex_t proc_map_lock;

void init_proc(void) {
    int id = idmap_alloc(&proc_map, &kernel_proc);
    if (id < 0) panic("failed to allocate id for kernel process (%d)", id);
    ASSERT(id == 0);

    proc_ref(&kernel_proc);
    list_insert_tail(&kernel_proc.tasks, &current_task->proc_node);
}

void proc_ref(proc_t *proc) {
    __atomic_fetch_add(&proc->references, 1, __ATOMIC_ACQUIRE);
}

void proc_deref(proc_t *proc) {
    while (__atomic_fetch_sub(&proc->references, 1, __ATOMIC_ACQUIRE) == 1) {
        proc_t *parent = proc->parent;

        mutex_lock(&proc_map_lock);
        idmap_free(&proc_map, proc->id);
        mutex_unlock(&proc_map_lock);

        kfree(proc);
        proc = parent;
    }
}

void proc_make_zombie(proc_t *proc) {
    mutex_unlock(&proc->lock);

    disable_preempt();

    list_foreach(proc->waiting_tasks, task_t, priv_node, cur) {
        sched_start(cur);
    }

    enable_preempt();
}

int create_thread(task_t **out, task_func_t func, void *ctx) {
    task_t *task;
    int error = sched_create(&task, func, ctx);
    if (error) return error;

    proc_ref(current_proc);
    task->process = current_proc;

    mutex_lock(&current_proc->lock);
    list_insert_tail(&current_proc->tasks, &task->proc_node);
    mutex_unlock(&current_proc->lock);

    sched_start(task);
    *out = task;
    return 0;
}

int create_process(proc_t **out, task_func_t func, void *ctx) {
    proc_t *proc = kalloc(sizeof(*proc));
    if (!proc) return ENOMEM;

    task_t *task;
    int error = sched_create(&task, func, ctx);
    if (error) {
        kfree(task);
        return error;
    }

    mutex_lock(&proc_map_lock);
    int id = idmap_alloc(&proc_map, proc);
    mutex_unlock(&proc_map_lock);

    if (id < 0) {
        task_deref(task);
        kfree(proc);
        return -id;
    }

    memset(proc, 0, sizeof(*proc));
    proc->references = 2;
    proc->parent = current_proc;
    proc->id = id;

    proc_ref(current_proc); // for proc->parent

    task->process = proc;
    list_insert_tail(&proc->tasks, &task->proc_node);

    sched_start(task);
    *out = proc;
    return 0;
}

bool proc_wait(proc_t *proc, uint64_t timeout) {
    irq_state_t state = save_disable_irq();

    bool success = list_is_empty(&proc->tasks);

    if (!success) {
        list_insert_tail(&proc->waiting_tasks, &current_task->priv_node);
        success = sched_stop(timeout);
        if (!success) list_remove(&proc->waiting_tasks, &current_task->priv_node);
    }

    restore_irq(state);
    return success;
}
