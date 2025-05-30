#pragma once

#include <stdbool.h>
#include <stdint.h>

extern int mem_fd; // fd for /dev/mem
extern int event_queue;
extern bool disable_interrupts;

typedef struct irq_handler {
    void (*func)(struct irq_handler *);
    int handle;
} irq_handler_t;

bool queue_task(void (*func)(void *), void *);
bool process_events(uint64_t deadline);
