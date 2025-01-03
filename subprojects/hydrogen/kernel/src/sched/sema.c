#include "sched/sema.h"
#include "asm/irq.h"
#include "cpu/cpu.h"
#include "sched/sched.h"
#include "util/list.h"
#include "util/spinlock.h"

// TODO: Make it so the fast paths (wait: non-zero, signal: there are no waiters) don't involve spinlocks

bool sema_try_wait(semaphore_t *sema) {
    irq_state_t state = spin_lock(&sema->lock);
    bool success = sema->value > 0;
    if (success) sema->value -= 1;
    spin_unlock(&sema->lock, state);
    return success;
}

bool sema_wait(semaphore_t *sema, uint64_t timeout) {
    irq_state_t state = spin_lock(&sema->lock);

    bool success = sema->value > 0;

    if (success) {
        sema->value -= 1;
    } else {
        list_insert_tail(&sema->waiters, &current_task->priv_node);
        success = sched_stop(timeout, &sema->lock);

        if (!success) {
            list_remove(&sema->waiters, &current_task->priv_node);
        }
    }

    spin_unlock(&sema->lock, state);
    return success;
}

void sema_signal(semaphore_t *sema) {
    irq_state_t state = save_disable_irq();
    disable_preempt();
    spin_lock_noirq(&sema->lock);

    task_t *task = node_to_obj(task_t, priv_node, list_remove_head(&sema->waiters));

    if (task == NULL) {
        sema->value += 1;
    } else {
        sched_start(task);
    }

    spin_unlock_noirq(&sema->lock);
    enable_preempt();
    restore_irq(state);
}

void sema_reset(semaphore_t *sema) {
    irq_state_t state = spin_lock(&sema->lock);
    sema->value = 0;
    spin_unlock(&sema->lock, state);
}
