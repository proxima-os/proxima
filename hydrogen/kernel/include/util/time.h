#ifndef HYDROGEN_UTIL_TIME_H
#define HYDROGEN_UTIL_TIME_H

#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t multiplier;
    unsigned shift;
} timeconv_t;

typedef struct timer_event {
    uint64_t timestamp;                    // read_time value at which the event is triggered
    void (*handler)(struct timer_event *); // executed in interrupt context
    // private fields
    struct cpu *cpu;
    struct timer_event *prev;
    struct timer_event *next;
    spinlock_t lock;
    bool queued;
} timer_event_t;

void init_time(void);

void init_time_cpu(void);

void queue_event(timer_event_t *event);

void cancel_event(timer_event_t *event);

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq);

uint64_t read_time(void);

// returns current posix time in nanoseconds
int64_t get_timestamp(void);

// sets the current posix time in nanoseconds
void set_timestamp(int64_t time);

static inline uint64_t timeconv_apply(timeconv_t conv, uint64_t value) {
    return ((__uint128_t)value * conv.multiplier) >> conv.shift;
}

#endif // HYDROGEN_UTIL_TIME_H
