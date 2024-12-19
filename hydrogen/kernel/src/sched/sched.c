#include "sched/sched.h"
#include "asm/irq.h"
#include "compiler.h"
#include "cpu/tss.h"
#include "errno.h"
#include "mem/heap.h"
#include "mem/memlayout.h"
#include "string.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

static void handle_timeout_expired(timer_event_t *event);

static void handle_switch_event(timer_event_t *event);

static task_t idle_task = {
        .state = TASK_RUNNING,
        .priority = -1,
        .timeout_event.handler = handle_timeout_expired,
};
task_t *current_task = &idle_task;

static list_t queues[SCHED_PRIO_MAX + 1];
static int cur_queue = -1;
static uint64_t queue_map;
static int preempt_level;
static uint64_t switch_time;
static timer_event_t switch_event = {.handler = handle_switch_event};

#define TIMESLICE_MIN 10000000ul // The time slice (in nanoseconds) used for priorities >= SCHED_RT_MIN
#define TIMESLICE_MAX 50000000ul // The time slice (in nanoseconds) used for priority 0
// The number of nanoseconds to increase the time slice by when moving up a queue.
// Only valid if the new queue <= SCHED_RT_MIN
#define TIMESLICE_INC ((TIMESLICE_MAX - TIMESLICE_MIN + (SCHED_RT_MIN / 2)) / SCHED_RT_MIN)

static uint64_t get_queue_timeslice(int queue) {
    uint64_t timeslice_ns = TIMESLICE_MIN;

    if (queue < SCHED_RT_MIN) {
        timeslice_ns += (SCHED_RT_MIN - queue) * TIMESLICE_INC;
    }

    return timeconv_apply(ns2tsc_conv, timeslice_ns);
}

static uint64_t queue_mask(int queue) {
    return 1ul << queue;
}

static void update_after_removal(int queue) {
    if (list_is_empty(&queues[queue])) {
        queue_map &= ~queue_mask(queue);
        cur_queue = queue_map ? 63 - __builtin_clzl(queue_map) : -1;
    }
}

// Ran right before switch_task
static void prepare_for_switch(UNUSED task_t *new_task) {
}

static void make_zombie(task_t *task) {
    task->state = TASK_ZOMBIE;
    kfree((void *)task->kernel_stack - KERNEL_STACK_SIZE);
}

// Ran right after switch_task
static void finish_switch(task_t *old_task) {
    kernel_tss.rsp[0] = current_task->kernel_stack;

    if (old_task->state == TASK_EXITING) {
        make_zombie(old_task);
        task_deref(old_task);
    }
}

extern void switch_task(task_ctx_t *from, task_ctx_t *to);

static void enqueue_task(task_t *task, bool front) {
    if (front) list_insert_head(&queues[task->priority], &task->node);
    else list_insert_tail(&queues[task->priority], &task->node);

    queue_map |= queue_mask(task->priority);
    if (task->priority > cur_queue) cur_queue = task->priority;
}

static void do_yield(bool preempt) {
    task_t *old_task = current_task;

    if (old_task->state == TASK_RUNNING) {
        if (old_task->priority >= 0) enqueue_task(old_task, preempt);
        old_task->state = TASK_READY;
    }

    if (preempt_level != 0) return;

    uint64_t time = read_time();
    uint64_t diff = switch_time - time;
    switch_time = time;

    old_task->runtime += diff;

    if (diff >= old_task->timeslice_rem) {
        old_task->timeslice_rem = old_task->timeslice_tot;
    } else {
        old_task->timeslice_rem -= diff;
    }

    task_t *new_task;

    if (cur_queue >= 0) {
        new_task = node_to_obj(task_t, node, list_remove_head(&queues[cur_queue]));
        update_after_removal(cur_queue);
    } else {
        new_task = &idle_task;
    }

    new_task->state = TASK_RUNNING;

    if (new_task->timeslice_rem != 0) {
        switch_event.timestamp = time + new_task->timeslice_rem;
        if (!switch_event.queued) queue_event(&switch_event);
    } else if (switch_event.queued) {
        cancel_event(&switch_event);
    }

    if (old_task != new_task) {
        prepare_for_switch(new_task);
        switch_task(&old_task->ctx, &new_task->ctx);
        task_t *old = current_task;
        current_task = old_task;
        finish_switch(old);
    }
}

void sched_yield(void) {
    irq_state_t state = save_disable_irq();
    do_yield(false);
    restore_irq(state);
}

void disable_preempt(void) {
    preempt_level += 1;
}

void enable_preempt(void) {
    if (--preempt_level == 0) {
        if (current_task->state != TASK_RUNNING) do_yield(false);
    }
}

bool sched_stop(uint64_t timeout) {
    ASSERT(current_task->priority >= 0); // verify this is not the idle task
    ASSERT(preempt_level == 0);

    irq_state_t state = save_disable_irq();
    current_task->state = TASK_STOPPED;
    current_task->timed_out = false;

    if (timeout != 0) {
        current_task->timeout_event.timestamp = timeout;
        queue_event(&current_task->timeout_event);
    }

    do_yield(false);

    restore_irq(state);
    return !current_task->timed_out;
}

static void check_preempt(void) {
    if (cur_queue > current_task->priority) do_yield(true);
}

void sched_start(task_t *task) {
    irq_state_t state = save_disable_irq();

    if (task->state == TASK_STOPPED) {
        task->state = TASK_RUNNING;
        if (task->timeout_event.queued) cancel_event(&task->timeout_event);

        enqueue_task(task, false);
        check_preempt();
    }

    restore_irq(state);
}

_Noreturn void sched_exit(void) {
    ASSERT(current_task->priority >= 0); // verify this is not the idle task

    disable_irq();

    ASSERT(preempt_level == 0);
    current_task->state = TASK_EXITING;
    do_yield(false);

    __builtin_unreachable();
}

static void handle_timeout_expired(timer_event_t *event) {
    task_t *task = node_to_obj(task_t, timeout_event, event);
    task->timed_out = true;
    sched_start(task);
}

static void handle_switch_event(UNUSED timer_event_t *event) {
    ASSERT(current_task->state == TASK_RUNNING);

    if (current_task->priority > 0 && current_task->priority < SCHED_RT_MIN) {
        current_task->priority -= 1;
        current_task->timeslice_tot += timeconv_apply(ns2tsc_conv, TIMESLICE_INC);
    }

    do_yield(false);
}

_Noreturn void sched_init_task(task_func_t func, void *ctx, task_t *task) {
    task_t *old = current_task;
    current_task = task;
    finish_switch(old);
    enable_irq();
    func(ctx);
    sched_exit();
}

extern const void task_init_stub;

int sched_create(task_t **out, task_func_t func, void *ctx) {
    task_t *task = kalloc(sizeof(*task));
    if (!task) return ENOMEM;
    memset(task, 0, sizeof(*task));

    void *stack = kalloc(KERNEL_STACK_SIZE);
    if (!stack) {
        kfree(task);
        return ENOMEM;
    }

    task->references = 2; // the returned task ptr and current_task for the task itself
    task->state = TASK_STOPPED;
    task->priority = SCHED_RT_MIN - 1;
    task->timeslice_tot = get_queue_timeslice(task->priority);
    task->timeslice_rem = task->timeslice_tot;

    task->ctx.rbx = (uintptr_t)func;
    task->ctx.r12 = (uintptr_t)ctx;
    task->ctx.r13 = (uintptr_t)task;
    task->kernel_stack = (uintptr_t)stack + KERNEL_STACK_SIZE;
    task->ctx.rsp = task->kernel_stack - sizeof(const void *);
    *(const void **)task->ctx.rsp = &task_init_stub;

    task->timeout_event.handler = handle_timeout_expired;

    *out = task;
    return 0;
}

void task_ref(task_t *task) {
    __atomic_fetch_add(&task->references, 1, __ATOMIC_ACQUIRE);
}

void task_deref(task_t *task) {
    if (__atomic_fetch_sub(&task->references, 1, __ATOMIC_ACQ_REL) == 1) {
        kfree(task);
    }
}
