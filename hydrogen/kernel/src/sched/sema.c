#include "sched/sema.h"
#include "asm/irq.h"
#include "sched/sched.h"
#include "util/list.h"

// TODO: Make it so the fast paths (wait: non-zero, signal: there are no waiters) don't involve disabling IRQs

bool sema_wait(semaphore_t *sema, uint64_t timeout) {
    irq_state_t state = save_disable_irq();

    bool success = sema->value > 0;

    if (success) {
        sema->value -= 1;
    } else {
        list_insert_tail(&sema->waiters, &current_task->node);
        success = sched_stop(timeout);
    }

    restore_irq(state);
    return success;
}

void sema_signal(semaphore_t *sema) {
    irq_state_t state = save_disable_irq();

    task_t *task = node_to_obj(task_t, node, list_remove_head(&sema->waiters));

    if (task == NULL) {
        sema->value += 1;
    } else {
        sched_start(task);
    }

    restore_irq(state);
}

void sema_reset(semaphore_t *sema) {
    irq_state_t state = save_disable_irq();
    sema->value = 0;
    restore_irq(state);
}
