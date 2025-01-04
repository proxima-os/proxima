#include "sched/sched.h"
#include "asm/fsgsbase.h"
#include "asm/irq.h"
#include "asm/msr.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "cpu/lapic.h"
#include "cpu/tss.h"
#include "cpu/xsave.h"
#include "hydrogen/error.h"
#include "mem/kvmm.h"
#include "mem/memlayout.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "mem/vmm.h"
#include "sched/proc.h"
#include "string.h"
#include "sys/vdso.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

static void handle_timeout_expired(timer_event_t *event);

static void handle_switch_event(timer_event_t *event);

#define TIMESLICE_MIN 10000000ul // The time slice (in nanoseconds) used for priorities >= SCHED_RT_MIN
#define TIMESLICE_MAX 50000000ul // The time slice (in nanoseconds) used for priority 0
// The number of nanoseconds to increase the time slice by when moving down a queue.
// Only valid if the new queue <= SCHED_RT_MIN
#define TIMESLICE_INC ((TIMESLICE_MAX - TIMESLICE_MIN + (SCHED_RT_MIN / 2)) / SCHED_RT_MIN)

// Every so often, the scheduler increases the priority of all non-real-time tasks by one to prevent starvation.
// This parameter determines how often that happens.
#define BOOST_INTERVAL_NS 1000000000ul

static uint64_t tsc_timeslice_min;
static uint64_t tsc_timeslice_inc;

static uint64_t get_queue_timeslice(int queue) {
    uint64_t timeslice = tsc_timeslice_min;

    if (queue < SCHED_RT_MIN) {
        timeslice += (SCHED_RT_MIN - queue) * tsc_timeslice_inc;
    }

    return timeslice;
}

static uint64_t queue_mask(int queue) {
    return 1ul << queue;
}

static void update_cur_queue(sched_t *sched) {
    sched->cur_queue = sched->queue_map ? 63 - __builtin_clzl(sched->queue_map) : -1;
}

static void update_after_removal(sched_t *sched, int queue) {
    if (list_is_empty(&sched->queues[queue])) {
        sched->queue_map &= ~queue_mask(queue);
        update_cur_queue(sched);
    }
}

// Ran right before switch_task
static void prepare_for_switch(UNUSED task_t *new_task) {
    xsave();

    if (fsgsbase_supported) {
        current_task->fs_base = rdfsbase();
        current_task->gs_base = rdmsr(MSR_KERNEL_GS_BASE);
    }
    // if fsgsbase isn't supported, current_task->{fs,gs}_base are up-to-date at all times
}

static void free_resources(task_t *task) {
    task->state = TASK_ZOMBIE;

    free_xsave(task->xsave_area);
    free_kernel_stack(task->kernel_stack);

    task->xsave_area = NULL;
    task->kernel_stack = 0;

    __atomic_fetch_sub(&task->cpu->sched.count, 1, __ATOMIC_RELAXED);
}

static list_t reaper_list;
static spinlock_t reaper_lock;
static task_t *reaper_task;

static void do_start(sched_t *sched, task_t *task);

// Ran right after switch_task
static void finish_switch(task_t *old_task) {
    xrestore();
    current_cpu.kernel_stack = (uintptr_t)current_task->kernel_stack;
    current_cpu.tss.rsp[0] = (uintptr_t)current_task->kernel_stack;

    wrmsr(MSR_FS_BASE, current_task->fs_base);
    wrmsr(MSR_KERNEL_GS_BASE, current_task->gs_base);

    vmm_t *vmm = current_proc->vmm;
    if (vmm != old_task->process->vmm) vmm_switch(vmm);

    if (old_task->state == TASK_EXITING) {
        spin_lock_noirq(&reaper_lock);
        list_insert_tail(&reaper_list, &old_task->priv_node);
        spin_unlock_noirq(&reaper_lock);

        if (reaper_task->cpu != current_cpu_ptr) spin_lock_noirq(&reaper_task->cpu->sched.lock);
        do_start(&reaper_task->cpu->sched, reaper_task);
        if (reaper_task->cpu != current_cpu_ptr) spin_unlock_noirq(&reaper_task->cpu->sched.lock);
    }
}

extern void switch_task(task_ctx_t *from, task_ctx_t *to);

static void enqueue_task(sched_t *sched, task_t *task, bool front) {
    if (front) list_insert_head(&sched->queues[task->priority], &task->node);
    else list_insert_tail(&sched->queues[task->priority], &task->node);

    sched->queue_map |= queue_mask(task->priority);
    if (task->priority > sched->cur_queue) sched->cur_queue = task->priority;
}

static void do_yield(sched_t *sched, bool preempt) {
    task_t *old_task = current_task;

    if (old_task->state == TASK_RUNNING) {
        if (old_task->priority >= 0) enqueue_task(sched, old_task, preempt);
        old_task->state = TASK_READY;
    }

    if (sched->preempt_level != 0) return;

    uint64_t time = read_time();
    uint64_t diff = time - sched->switch_time;
    sched->switch_time = time;

    old_task->runtime += diff;

    if (diff >= old_task->timeslice_rem) {
        old_task->timeslice_rem = old_task->timeslice_tot;
    } else {
        old_task->timeslice_rem -= diff;
    }

    task_t *new_task;

    if (sched->cur_queue >= 0) {
        new_task = node_to_obj(task_t, node, list_remove_head(&sched->queues[sched->cur_queue]));
        update_after_removal(sched, sched->cur_queue);
    } else {
        new_task = &current_cpu_ptr->sched.idle;
    }

    new_task->state = TASK_RUNNING;
    cancel_event(&sched->switch_event);

    if (new_task->timeslice_rem != 0) {
        sched->switch_event.timestamp = time + new_task->timeslice_rem;
        queue_event(&sched->switch_event);
    }

    if (old_task != new_task) {
        prepare_for_switch(new_task);
        switch_task(&old_task->ctx, &new_task->ctx);
        task_t *old = current_task;
        current_task = old_task;
        finish_switch(old);
    }
}

static void check_preempt(sched_t *sched) {
    if (sched->cur_queue > sched->current->priority) {
        if (sched == &current_cpu_ptr->sched) do_yield(sched, true);
        else lapic_send_ipi((cpu_t *)node_to_obj(cpu_t, sched, sched), IPI_RESCHEDULE);
    }
}

static void boost_task_func(UNUSED void *ctx) {
    sched_set_priority(current_task, SCHED_PRIO_MAX, true);

    uint64_t interval = timeconv_apply(ns2tsc_conv, BOOST_INTERVAL_NS);
    uint64_t time = read_time() + interval;

    for (;;) {
        sched_stop(time, NULL);
        time += interval;

        for (cpu_t *cur = boot_cpu; cur != NULL; cur = cur->next) {
            sched_t *sched = &cur->sched;

            irq_state_t state = spin_lock(&cur->sched.lock);

            for (int i = SCHED_RT_MIN - 2; i >= 0; i--) {
                if ((sched->queue_map & queue_mask(i)) == 0) continue;

                list_foreach(sched->queues[i], task_t, node, cur) {
                    cur->priority += 1;
                    cur->timeslice_tot -= tsc_timeslice_inc;
                }

                list_transfer_tail(&sched->queues[i + 1], &sched->queues[i]);

                sched->queue_map &= ~queue_mask(i);
                sched->queue_map |= queue_mask(i + 1);
            }

            update_cur_queue(sched);

            spin_unlock(&sched->lock, state);
        }
    }
}

static void reaper_func(UNUSED void *ctx) {
    for (;;) {
        irq_state_t state = spin_lock(&reaper_lock);
        while (list_is_empty(&reaper_list)) sched_stop(0, &reaper_lock);
        task_t *task = node_to_obj(task_t, priv_node, list_remove_head(&reaper_list));
        spin_unlock(&reaper_lock, state);

        free_resources(task);

        state = save_disable_irq();
        disable_preempt();

        spin_lock_noirq(&task->process->lock);

        list_remove(&task->process->tasks, &task->proc_node);
        if (list_is_empty(&task->process->tasks)) proc_make_zombie(task->process);

        spin_unlock_noirq(&task->process->lock);
        spin_lock_noirq(&task->wait_lock);

        task->already_exited = true;

        task_t *cur = node_to_obj(task_t, priv_node, task->waiting_tasks.first);
        while (cur != NULL) {
            task_t *next = node_to_obj(task_t, priv_node, cur->priv_node.next);
            sched_start(cur);
            cur = next;
        }

        spin_unlock_noirq(&task->wait_lock);
        enable_preempt();
        restore_irq(state);

        proc_deref(task->process);
        task->process = NULL;

        task_deref(task);
    }
}

static void handle_ipi_reschedule(UNUSED idt_frame_t *frame) {
    sched_t *sched = &current_cpu_ptr->sched;
    spin_lock_noirq(&sched->lock);

    lapic_eoi();
    if (sched->cur_queue > current_task->priority) {
        do_yield(sched, true);
    }

    spin_unlock_noirq(&sched->lock);
}

void init_sched(void) {
    idt_install(IPI_RESCHEDULE, handle_ipi_reschedule);

    tsc_timeslice_min = timeconv_apply(ns2tsc_conv, TIMESLICE_MIN);
    tsc_timeslice_inc = timeconv_apply(ns2tsc_conv, TIMESLICE_INC);

    task_t *task;
    int error = create_thread(&task, boost_task_func, NULL, NULL);
    if (error) panic("failed to create priority boost task (%d)", error);
    task_deref(task);

    error = create_thread(&reaper_task, reaper_func, NULL, NULL);
    if (error) panic("failed to create reaper task (%d)", error);
}

void init_sched_cpu(void) {
    current_cpu.sched.current = &current_cpu_ptr->sched.idle;
    current_cpu.sched.switch_event.handler = handle_switch_event;
    current_cpu.sched.cur_queue = -1;

    current_task->state = TASK_RUNNING;
    current_task->priority = -1;
    current_task->timeout_event.handler = handle_timeout_expired;
    current_task->process = &kernel_proc;
    proc_ref(current_proc);

    irq_state_t state = spin_lock(&current_proc->lock);
    list_insert_tail(&current_proc->tasks, &current_task->proc_node);
    spin_unlock(&current_proc->lock, state);
}

void sched_yield(void) {
    irq_state_t state = save_disable_irq();
    sched_t *sched = &current_cpu_ptr->sched;
    spin_lock_noirq(&sched->lock);
    do_yield(sched, false);
    spin_unlock_noirq(&sched->lock);
    restore_irq(state);
}

void disable_preempt(void) {
    current_cpu.sched.preempt_level += 1;
}

void enable_preempt(void) {
    if (--current_cpu.sched.preempt_level == 0) {
        sched_t *sched = &current_cpu_ptr->sched;
        spin_lock_noirq(&sched->lock);
        if (current_task->state != TASK_RUNNING) do_yield(sched, false);
        spin_unlock_noirq(&sched->lock);
    }
}

bool sched_stop(uint64_t timeout, spinlock_t *lock) {
    irq_state_t state = save_disable_irq();

    ASSERT(current_task->priority >= 0); // verify this is not the idle task
    ASSERT(current_cpu.sched.preempt_level == 0);

    sched_t *sched = &current_cpu_ptr->sched;
    spin_lock_noirq(&sched->lock);

    current_task->state = TASK_STOPPED;
    current_task->timed_out = false;

    if (timeout != 0) {
        current_task->timeout_event.timestamp = timeout;
        queue_event(&current_task->timeout_event);
    }

    if (lock) spin_unlock_noirq(lock);
    do_yield(sched, false);

    if (lock) {
        // the extra lock/unlock of the scheduler lock is needed to avoid a deadlock
        spin_unlock_noirq(&sched->lock);
        spin_lock_noirq(lock);
        spin_lock_noirq(&sched->lock);
    }

    bool success = !current_task->timed_out;

    spin_unlock_noirq(&sched->lock);
    restore_irq(state);
    return success;
}

static void do_start(sched_t *sched, task_t *task) {
    if (task->state == TASK_EMBRYO) {
        task_ref(task);
        task->state = TASK_STOPPED;
    }

    if (task->state == TASK_STOPPED) {
        task->state = TASK_READY;
        cancel_event(&task->timeout_event);

        enqueue_task(sched, task, false);
        check_preempt(sched);
    }
}

void sched_start(task_t *task) {
    sched_t *sched = &task->cpu->sched;
    irq_state_t state = spin_lock(&sched->lock);

    task->timed_out = false;
    do_start(sched, task);

    spin_unlock(&sched->lock, state);
}

_Noreturn void sched_exit(void) {
    disable_irq();

    ASSERT(current_task->priority >= 0); // verify this is not the idle task
    ASSERT(current_cpu.sched.preempt_level == 0);

    sched_t *sched = &current_cpu_ptr->sched;
    spin_lock_noirq(&sched->lock);

    current_task->state = TASK_EXITING;
    do_yield(sched, false);

    __builtin_unreachable();
}

static void handle_timeout_expired(timer_event_t *event) {
    task_t *task = node_to_obj(task_t, timeout_event, event);
    sched_t *sched = &task->cpu->sched;
    spin_lock_noirq(&sched->lock);

    if (task->state == TASK_STOPPED) {
        task->timed_out = true;
        do_start(sched, task);
    }

    spin_unlock_noirq(&sched->lock);
}

static void handle_switch_event(UNUSED timer_event_t *event) {
    sched_t *sched = &current_cpu_ptr->sched;
    spin_lock_noirq(&sched->lock);

    if (likely(current_task->state != TASK_READY)) {
        ASSERT(current_task->state == TASK_RUNNING);

        if (current_task->priority > 0 && current_task->priority < SCHED_RT_MIN) {
            current_task->priority -= 1;
            current_task->timeslice_tot += tsc_timeslice_inc;
        }
    }

    do_yield(sched, false);
    spin_unlock_noirq(&sched->lock);
}

_Noreturn void sched_init_task(task_func_t func, void *ctx, task_t *task) {
    task_t *old = current_task;
    current_task = task;
    finish_switch(old);
    spin_unlock_noirq(&current_cpu_ptr->sched.lock);
    enable_irq();
    func(ctx);
    sched_exit();
}

extern const void task_init_stub;

int sched_create(task_t **out, task_func_t func, void *ctx, struct cpu *cpu) {
    task_t *task = vmalloc(sizeof(*task));
    if (!task) return ERR_OUT_OF_MEMORY;

    void *xsave = alloc_xsave();
    if (!xsave) {
        vmfree(task, sizeof(*task));
        return ERR_OUT_OF_MEMORY;
    }

    void *stack = allocate_kernel_stack();
    ;
    if (!stack) {
        free_xsave(xsave);
        vmfree(task, sizeof(*task));
        return ERR_OUT_OF_MEMORY;
    }

    memset(task, 0, sizeof(*task));
    task->references = 1;
    task->state = TASK_EMBRYO;
    task->priority = SCHED_RT_MIN - 1;
    task->timeslice_tot = get_queue_timeslice(task->priority);
    task->timeslice_rem = task->timeslice_tot;

    task->ctx.rbx = (uintptr_t)func;
    task->ctx.r12 = (uintptr_t)ctx;
    task->ctx.r13 = (uintptr_t)task;
    task->kernel_stack = stack;
    task->ctx.rsp = (uintptr_t)task->kernel_stack - sizeof(uintptr_t) * 2;
    task->xsave_area = xsave;

    uintptr_t *stack_frame = (uintptr_t *)task->ctx.rsp;
    stack_frame[0] = 0;                          // rflags
    stack_frame[1] = (uintptr_t)&task_init_stub; // return address

    task->timeout_event.handler = handle_timeout_expired;

    if (!cpu) {
        cpu_t *cur_best_cpu = NULL;
        uint64_t cur_best_cnt = UINT64_MAX;

        for (cpu_t *cpu = boot_cpu; cpu != NULL; cpu = cpu->next) {
            uint64_t count = __atomic_load_n(&cpu->sched.count, __ATOMIC_RELAXED);
            if (count < cur_best_cnt) {
                cur_best_cpu = cpu;
                cur_best_cnt = count;
            }
        }

        task->cpu = cur_best_cpu;
    } else {
        task->cpu = cpu;
    }

    __atomic_fetch_add(&task->cpu->sched.count, 1, __ATOMIC_RELAXED);

    *out = task;
    return 0;
}

void task_ref(task_t *task) {
    __atomic_fetch_add(&task->references, 1, __ATOMIC_ACQUIRE);
}

void task_deref(task_t *task) {
    if (__atomic_fetch_sub(&task->references, 1, __ATOMIC_ACQ_REL) == 1) {
        if (task->state == TASK_EMBRYO) free_resources(task);
        vmfree(task, sizeof(*task));
    }
}

void sched_set_priority(task_t *task, int priority, bool inf_timeslice) {
    sched_t *sched = &task->cpu->sched;
    irq_state_t state = spin_lock(&sched->lock);

    if (priority < SCHED_RT_MIN) {
        if (task->priority >= SCHED_RT_MIN) {
            priority = SCHED_RT_MIN - 1;
            inf_timeslice = false;
        } else {
            spin_unlock(&sched->lock, state);
            return;
        }
    }

    if (task->priority != priority) {
        if (task->state == TASK_READY) {
            list_remove(&sched->queues[task->priority], &task->node);
            if (list_is_empty(&sched->queues[task->priority])) sched->queue_map &= ~queue_mask(task->priority);

            if (priority < task->priority) list_insert_head(&sched->queues[priority], &task->node);
            else list_insert_tail(&sched->queues[priority], &task->node);
            sched->queue_map |= queue_mask(priority);

            update_cur_queue(sched);
        }

        task->priority = priority;
    }

    task->timeslice_tot = !inf_timeslice ? get_queue_timeslice(priority) : 0;

    check_preempt(sched);
    spin_unlock(&sched->lock, state);
}

bool sched_wait(task_t *task, uint64_t timeout) {
    irq_state_t state = spin_lock(&task->wait_lock);

    if (!task->already_exited) {
        list_insert_tail(&task->waiting_tasks, &current_task->priv_node);

        if (!sched_stop(timeout, &task->wait_lock)) {
            list_remove(&task->waiting_tasks, &current_task->priv_node);
        }
    }

    spin_unlock(&task->wait_lock, state);
    return state;
}

_Static_assert(KERNEL_STACK_SIZE % PAGE_SIZE == 0, "KERNEL_STACK_SIZE is not a multiple of PAGE_SIZE");

void *allocate_kernel_stack(void) {
    size_t pages = KERNEL_STACK_SIZE >> PAGE_SHIFT;
    if (unlikely(!reserve_pages(pages))) return NULL;

    size_t vaddr;
    if (unlikely(!vmem_alloc(&kvmm, KERNEL_STACK_SIZE + PAGE_SIZE, &vaddr))) {
        unreserve_pages(pages);
        return NULL;
    }

    int error = prepare_map(vaddr + PAGE_SIZE, KERNEL_STACK_SIZE);
    if (error) {
        vmem_free(&kvmm, vaddr, KERNEL_STACK_SIZE + PAGE_SIZE);
        unreserve_pages(pages);
        return NULL;
    }

    alloc_and_map(vaddr + PAGE_SIZE, KERNEL_STACK_SIZE);
    return (void *)(vaddr + PAGE_SIZE + KERNEL_STACK_SIZE);
}

void free_kernel_stack(void *stack) {
    uintptr_t vaddr = (uintptr_t)stack - KERNEL_STACK_SIZE - PAGE_SIZE;
    unmap(vaddr + PAGE_SIZE, KERNEL_STACK_SIZE);
    vmem_free(&kvmm, vaddr, KERNEL_STACK_SIZE + PAGE_SIZE);
    unreserve_pages(KERNEL_STACK_SIZE >> PAGE_SHIFT);
}
