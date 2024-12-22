#ifndef HYDROGEN_SCHED_PROC_H
#define HYDROGEN_SCHED_PROC_H

#include "sched/mutex.h"
#include "sched/sched.h"
#include "util/list.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t references;
    uint32_t uid;
    uint32_t gid;
} identity_t;

typedef struct proc {
    size_t references;
    proc_t *parent;
    int id;

    mutex_t lock;
    list_t tasks;
    list_t waiting_tasks;

    identity_t *identity;
    uint32_t umask;
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

identity_t *get_identity(void);

void ident_ref(identity_t *ident);

void ident_deref(identity_t *ident);

void set_identity(identity_t *identity);

#endif // HYDROGEN_SCHED_PROC_H
