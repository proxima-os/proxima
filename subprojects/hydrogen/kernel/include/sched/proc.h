#ifndef HYDROGEN_SCHED_PROC_H
#define HYDROGEN_SCHED_PROC_H

#include "cpu/cpu.h"
#include "fs/vfs.h"
#include "mem/vmm.h"
#include "sched/sched.h"
#include "util/list.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct ident {
    size_t references;
    uint32_t uid;
    uint32_t gid;
} ident_t;

typedef struct proc {
    size_t references;
    proc_t *parent;
    vmm_t *vmm;
    uintptr_t vdso;
    int id;

    spinlock_t lock;
    list_t tasks;
    list_t waiting_tasks;

    ident_t *identity;
    vnode_t *root;
    uint32_t umask;
} proc_t;

extern proc_t kernel_proc;

#define current_proc (current_task->process)

void init_proc(void);

void proc_ref(proc_t *proc);

void proc_deref(proc_t *proc);

// must be called with proc->lock held and preemption disabled
void proc_make_zombie(proc_t *proc);

int create_thread(task_t **out, task_func_t func, void *ctx, cpu_t *cpu);

int create_process(proc_t **out, task_func_t func, void *ctx, vmm_t *vmm);

// waits until all tasks in `proc` exit, `timeout` has the same meaning as in `sched_stop`
bool proc_wait(proc_t *proc, uint64_t timeout);

ident_t *get_identity(void);

void ident_ref(ident_t *ident);

void ident_deref(ident_t *ident);

void set_identity(ident_t *identity);

vnode_t *get_root(void);

void set_root(vnode_t *vnode);

#endif // HYDROGEN_SCHED_PROC_H
