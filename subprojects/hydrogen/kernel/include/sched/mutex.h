#ifndef HYDROGEN_SCHED_MUTEX_H
#define HYDROGEN_SCHED_MUTEX_H

#include "util/list.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char state;
    spinlock_t lock;
    list_t waiters;
} mutex_t;

void mutex_lock(mutex_t *mutex);

// `timeout` has the same meaning as in `sched_stop`
bool mutex_lock_timeout(mutex_t *mutex, uint64_t timeout);

bool mutex_try_lock(mutex_t *mutex);

void mutex_unlock(mutex_t *mutex);

#endif // HYDROGEN_SCHED_MUTEX_H
