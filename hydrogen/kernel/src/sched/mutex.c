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

static inline bool do_cmpxchg(char *state, char *wanted, char value) {
    bool success;
    asm volatile("cmpxchg %[value], %[state]"
                 : "=@ccz"(success), "+a"(*wanted), [state] "+m" (*state)
                 : [value] "r"(value));
    return success;
}

bool mutex_try_lock(mutex_t *mutex) {
    char wanted = MUTEX_UNLOCKED;
    return do_cmpxchg(&mutex->state, &wanted, MUTEX_LOCKED_NOQUEUE);
}

void mutex_lock(mutex_t *mutex) {
    mutex_lock_timeout(mutex, 0);
}

bool mutex_lock_timeout(mutex_t *mutex, uint64_t timeout) {
    for (int i = 0; i < SPIN_ITERS; i++) {
        char wanted = MUTEX_UNLOCKED;

        if (do_cmpxchg(&mutex->state, &wanted, MUTEX_LOCKED_NOQUEUE)) {
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
        list_insert_tail(&mutex->waiters, &current_task->priv_node);
        success = sched_stop(timeout);

        if (!success) {
            list_remove(&mutex->waiters, &current_task->priv_node);
        }
    } else {
        mutex->state = MUTEX_LOCKED_NOQUEUE;
    }

    restore_irq(state);
    return success;
}

void mutex_unlock(mutex_t *mutex) {
    char wanted = MUTEX_LOCKED_NOQUEUE;
    if (do_cmpxchg(&mutex->state, &wanted, MUTEX_UNLOCKED)) {
        return;
    }

    // If it's neither this nor MUTEX_LOCKED_NOQUEUE, someone else unlocked the mutex even though we owned it
    ASSERT(wanted == MUTEX_LOCKED_QUEUED);

    irq_state_t state = save_disable_irq();

    // Don't need to check mutex->state again, since it can only be moved off of MUTEX_LOCKED_* by mutex_unlock
    task_t *task = node_to_obj(task_t, priv_node, list_remove_head(&mutex->waiters));
    if (list_is_empty(&mutex->waiters)) mutex->state = MUTEX_LOCKED_NOQUEUE;
    sched_start(task);

    restore_irq(state);
}
