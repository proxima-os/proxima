#include "sched/mutex.h"
#include "asm/irq.h"
#include "proxima/compiler.h"
#include "cpu/cpu.h"
#include "sched/sched.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdatomic.h>

#define SPIN_ITERS 40

#define MUTEX_UNLOCKED 0
#define MUTEX_LOCKED 1
#define MUTEX_CONTESTED 2

bool mutex_try_lock(mutex_t *mutex) {
    char wanted = MUTEX_UNLOCKED;
    return __atomic_compare_exchange_n(&mutex->state, &wanted, MUTEX_LOCKED, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

void mutex_lock(mutex_t *mutex) {
    mutex_lock_timeout(mutex, 0);
}

static bool try_lock_weak(mutex_t *mutex) {
    char wanted = MUTEX_UNLOCKED;

    return __atomic_compare_exchange_n(&mutex->state, &wanted, MUTEX_LOCKED, true, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

bool mutex_lock_timeout(mutex_t *mutex, uint64_t timeout) {
    if (likely(try_lock_weak(mutex))) return true;

    for (int i = 0; i < SPIN_ITERS; i++) {
        if (likely(try_lock_weak(mutex))) return true;

        sched_yield();
    }

    irq_state_t state = spin_lock(&mutex->lock);

    bool success;

    if (likely(__atomic_exchange_n(&mutex->state, MUTEX_CONTESTED, __ATOMIC_ACQ_REL) != MUTEX_UNLOCKED)) {
        list_insert_tail(&mutex->waiters, &current_task->priv_node);
        success = sched_stop(timeout, &mutex->lock);
        if (!success) list_remove(&mutex->waiters, &current_task->priv_node);
    } else {
        // not racy because we own the spinlock
        __atomic_store_n(&mutex->state, MUTEX_LOCKED, __ATOMIC_RELEASE);
        success = true;
    }

    spin_unlock(&mutex->lock, state);
    return success;
}

void mutex_unlock(mutex_t *mutex) {
    char wanted = MUTEX_LOCKED;
    if (likely(__atomic_compare_exchange_n(
                &mutex->state,
                &wanted,
                MUTEX_UNLOCKED,
                false,
                __ATOMIC_ACQ_REL,
                __ATOMIC_RELAXED
        ))) {
        return;
    }

    // If it's neither this nor MUTEX_LOCKED, someone else unlocked the mutex even though we owned it
    // Note that a mutex can only be moved off of CONTESTED by the owner of the lock (us) calling mutex_unlock
    ASSERT(wanted == MUTEX_CONTESTED);

    irq_state_t state = save_disable_irq();
    disable_preempt();
    spin_lock_noirq(&mutex->lock);

    task_t *task = node_to_obj(task_t, priv_node, list_remove_head(&mutex->waiters));

    if (task) {
        if (list_is_empty(&mutex->waiters)) __atomic_store_n(&mutex->state, MUTEX_LOCKED, __ATOMIC_RELEASE);
        sched_start(task);
    } else {
        __atomic_store_n(&mutex->state, MUTEX_UNLOCKED, __ATOMIC_RELEASE);
    }

    spin_unlock_noirq(&mutex->lock);
    enable_preempt();
    restore_irq(state);
}
