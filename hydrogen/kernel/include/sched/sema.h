#ifndef HYDROGEN_SCHED_SEMA_H
#define HYDROGEN_SCHED_SEMA_H

#include "util/list.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t value;
    list_t waiters;
    spinlock_t lock;
} semaphore_t;

bool sema_try_wait(semaphore_t *sema);

// `timeout` has the same meaning as in `sched_stop`
bool sema_wait(semaphore_t *sema, uint64_t timeout);

void sema_signal(semaphore_t *sema);

void sema_reset(semaphore_t *sema);

#endif // HYDROGEN_SCHED_SEMA_H
