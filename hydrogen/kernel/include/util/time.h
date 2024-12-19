#ifndef HYDROGEN_UTIL_TIME_H
#define HYDROGEN_UTIL_TIME_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t multiplier;
    unsigned shift;
} timeconv_t;

typedef struct timer_event {
    uint64_t timestamp;                    // read_time value at which the event is triggered
    void (*handler)(struct timer_event *); // executed in interrupt context
    bool queued;                           // read-only
    // private fields
    struct timer_event *parent;
    struct timer_event *left;
    struct timer_event *right;
} timer_event_t;

extern uint64_t tsc_freq;
extern uint64_t boot_tsc;
extern timeconv_t tsc2ns_conv;
extern timeconv_t ns2tsc_conv;

void init_time(void);

void queue_event(timer_event_t *event);

void cancel_event(timer_event_t *event);

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq);

static inline uint64_t read_time(void) {
    return __builtin_ia32_rdtsc() - boot_tsc;
}

static inline uint64_t timeconv_apply(timeconv_t conv, uint64_t value) {
    return ((__uint128_t)value * conv.multiplier) >> conv.shift;
}

#endif // HYDROGEN_UTIL_TIME_H
