#ifndef HYDROGEN_SCHED_SCHED_H
#define HYDROGEN_SCHED_SCHED_H

#include "util/list.h"
#include "util/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SCHED_PRIO_MAX 63

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
} task_state_t;

typedef struct {
    size_t references;

    list_node_t node;
    task_state_t state;
    int priority;

    task_ctx_t ctx;
    uintptr_t kernel_stack;

    timer_event_t timeout_event;
    bool timed_out;
} task_t;

extern task_t *current_task;

typedef void (*task_func_t)(void *);

void sched_yield(void);

void disable_preempt(void);

void enable_preempt(void);

// if `timeout` isn't 0, as soon as `read_time` exceeds it, this function will return false.
bool sched_stop(uint64_t timeout);

void sched_start(task_t *task);

_Noreturn void sched_exit(void);

int sched_create(task_t **out, task_func_t func, void *ctx);

void task_ref(task_t *task);

void task_deref(task_t *task);

#endif // HYDROGEN_SCHED_SCHED_H
