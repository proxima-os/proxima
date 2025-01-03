#ifndef HYDROGEN_SCHED_SCHED_H
#define HYDROGEN_SCHED_SCHED_H

#include "util/list.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SCHED_RT_MIN 32 // Tasks at or above this priority are subject to real-time (round-robin or FIFO) scheduling
#define SCHED_PRIO_MAX 63

typedef struct proc proc_t;

typedef struct {
    size_t rbx;
    size_t rbp;
    size_t rsp;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
} task_ctx_t;

typedef enum {
    TASK_RUNNING,
    TASK_READY,
    TASK_STOPPED,
    TASK_EXITING,
    TASK_ZOMBIE,
    TASK_EMBRYO,
} task_state_t;

typedef struct {
    struct cpu *cpu;
    size_t references;

    list_node_t node;
    task_state_t state;
    int priority;

    task_ctx_t ctx;
    void *xsave_area;
    void *kernel_stack;
    uintptr_t fs_base;
    uintptr_t gs_base;

    timer_event_t timeout_event;
    bool timed_out;

    list_node_t priv_node;

    uint64_t timeslice_tot; // total length of the task's time slice in tsc ticks (0 is infinite)
    uint64_t timeslice_rem; // remaining time slice in tsc ticks
    uint64_t runtime;       // total runtime of this task in tsc ticks

    proc_t *process;
    list_node_t proc_node;

    spinlock_t wait_lock;
    bool already_exited;
    list_t waiting_tasks;
} task_t;

typedef struct {
    list_t queues[SCHED_PRIO_MAX + 1];
    int cur_queue;
    int preempt_level;
    uint64_t queue_map;
    uint64_t switch_time;
    timer_event_t switch_event;
    spinlock_t lock;
    uint64_t count;

    task_t *current;
    task_t idle;
} sched_t;

typedef void (*task_func_t)(void *);

void init_sched(void);

void init_sched_cpu(void);

void sched_yield(void);

// note: irqs *can* be enabled while preemption is disabled
void disable_preempt(void);

void enable_preempt(void);

// if `timeout` isn't 0, as soon as `read_time` exceeds it, this function will return false.
// if `lock` isn't null, it's unlocked before yielding and relocked afterwards in a way that avoids lost wakeups
bool sched_stop(uint64_t timeout, spinlock_t *lock);

void sched_start(task_t *task);

_Noreturn void sched_exit(void);

int sched_create(task_t **out, task_func_t func, void *ctx, struct cpu *cpu);

void task_ref(task_t *task);

void task_deref(task_t *task);

void sched_set_priority(task_t *task, int priority, bool inf_timeslice);

// Waits until the given task exits. Timeout has the same meaning as in sched_stop
bool sched_wait(task_t *task, uint64_t timeout);

_Noreturn void enter_user_mode(uintptr_t rip, uintptr_t rsp);

// returns the top of the stack
void *allocate_kernel_stack(void);

void free_kernel_stack(void *stack);

#endif // HYDROGEN_SCHED_SCHED_H
