#include "sched/mutex.h"
#include "asm/irq.h"
#include "sched/sched.h"
#include "util/list.h"
#include "util/panic.h"
#include <stdatomic.h>

#define SPIN_ITERS 40

#define MUTEX_UNLOCKED 0
#define MUTEX_LOCKED_NOQUEUE 1
#define MUTEX_LOCKED_QUEUED 2

bool mutex_try_lock(mutex_t *mutex) {
    int wanted = MUTEX_UNLOCKED;
    return __atomic_compare_exchange_n(
            &mutex->state,
            &wanted,
            MUTEX_LOCKED_NOQUEUE,
            true,
            __ATOMIC_ACQUIRE,
            __ATOMIC_RELAXED
    );
}

void mutex_lock(mutex_t *mutex) {
    mutex_lock_timeout(mutex, 0);
}

bool mutex_lock_timeout(mutex_t *mutex, uint64_t timeout) {
    for (int i = 0; i < SPIN_ITERS; i++) {
        int wanted = MUTEX_UNLOCKED;

        if (__atomic_compare_exchange_n(
                    &mutex->state,
                    &wanted,
                    MUTEX_LOCKED_NOQUEUE,
                    true,
                    __ATOMIC_ACQUIRE,
                    __ATOMIC_RELAXED
            )) {
            return true;
        }

        if (wanted == MUTEX_LOCKED_QUEUED) break;
        sched_yield();
    }

    irq_state_t state = save_disable_irq();

    // IRQs are disabled, so mutex state can now be accessed without atomics
    bool success = mutex->state == MUTEX_UNLOCKED;

    if (!success) {
        mutex->state = MUTEX_LOCKED_QUEUED;
        list_insert_tail(&mutex->waiters, &current_task->node);
        sched_stop(timeout);
    } else {
        mutex->state = MUTEX_LOCKED_NOQUEUE;
    }

    restore_irq(state);
    return success;
}

void mutex_unlock(mutex_t *mutex) {
    int wanted = MUTEX_LOCKED_NOQUEUE;
    if (__atomic_compare_exchange_n(
                &mutex->state,
                &wanted,
                MUTEX_UNLOCKED,
                false,
                __ATOMIC_RELEASE,
                __ATOMIC_RELAXED
        )) {
        return;
    }

    // If it's neither this nor MUTEX_LOCKED_NOQUEUE, someone else unlocked the mutex even though we owned it
    ASSERT(wanted == MUTEX_LOCKED_QUEUED);

    irq_state_t state = save_disable_irq();

    // Don't need to check mutex->state again, since it can only be moved off of MUTEX_LOCKED_* by mutex_unlock
    task_t *task = node_to_obj(task_t, node, list_remove_head(&mutex->waiters));
    if (list_is_empty(&mutex->waiters)) mutex->state = MUTEX_LOCKED_NOQUEUE;
    sched_start(task);

    restore_irq(state);
}
