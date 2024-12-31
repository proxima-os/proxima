#ifndef HYDROGEN_UTIL_SPINLOCK_H
#define HYDROGEN_UTIL_SPINLOCK_H

#include "asm/irq.h"

typedef struct {
    char state;
} spinlock_t;

irq_state_t spin_lock(spinlock_t *lock);

void spin_unlock(spinlock_t *lock, irq_state_t state);

void spin_lock_noirq(spinlock_t *lock);

void spin_unlock_noirq(spinlock_t *lock);

#endif // HYDROGEN_UTIL_SPINLOCK_H
