#include "util/spinlock.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include <stdbool.h>

irq_state_t spin_lock(spinlock_t *lock) {
    irq_state_t state = save_disable_irq();
    spin_lock_noirq(lock);
    return state;
}

void spin_unlock(spinlock_t *lock, irq_state_t state) {
    spin_unlock_noirq(lock);
    restore_irq(state);
}

void spin_lock_noirq(spinlock_t *lock) {
    char wanted = 0;

    while (!__atomic_compare_exchange_n(&lock->state, &wanted, 1, true, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
        cpu_relax();
        wanted = 0;
    }
}

void spin_unlock_noirq(spinlock_t *lock) {
    __atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE);
}
