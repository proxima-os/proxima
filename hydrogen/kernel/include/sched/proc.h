#ifndef HYDROGEN_SCHED_PROC_H
#define HYDROGEN_SCHED_PROC_H

#include "sched/mutex.h"
#include "sched/sched.h"
#include "util/list.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct proc {
    size_t references;
    proc_t *parent;
    int id;

    mutex_t lock;
    list_t tasks;
    list_t waiting_tasks;
} proc_t;

extern proc_t kernel_proc;

#define current_proc (current_task->process)

void init_proc(void);

void proc_ref(proc_t *proc);

void proc_deref(proc_t *proc);

// must be called with proc->lock held and irqs disabled, unlocks proc->lock
void proc_make_zombie(proc_t *proc);

int create_thread(task_t **out, task_func_t func, void *ctx);

int create_process(proc_t **out, task_func_t func, void *ctx);

// waits until all tasks in `proc` exit, `timeout` has the same meaning as in `sched_stop`
bool proc_wait(proc_t *proc, uint64_t timeout);

#endif // HYDROGEN_SCHED_PROC_H
