#include "main.h"
#include "acpi/acpi.h"
#include "acpi/serial.h"
#include "compiler.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <hydrogen/eventqueue.h>
#include <hydrogen/handle.h>
#include <hydrogen/interrupt.h>
#include <hydrogen/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __x86_64__
#include <hydrogen/x86_64/io.h>
#endif

int mem_fd;
int event_queue;
bool disable_interrupts;

static void setup_hw_access(void) {
    mem_fd = open("/dev/mem", O_RDWR | O_CLOEXEC);
    if (mem_fd < 0) {
        perror("devicesd: failed to open /dev/mem");
        exit(EXIT_FAILURE);
    }

#ifdef __x86_64__
    int error = hydrogen_x86_64_enable_io_access();
    if (error) {
        fprintf(stderr, "devicesd: failed to enable i/o port access (%s)\n", strerror(error));
        exit(EXIT_FAILURE);
    }
#endif
}

static void setup_events(void) {
    hydrogen_ret_t queue = hydrogen_event_queue_create(HYDROGEN_HANDLE_CLONE_KEEP);
    if (queue.error) {
        fprintf(stderr, "devicesd: failed to create event queue (%s)\n", strerror(queue.error));
        exit(EXIT_FAILURE);
    }
    event_queue = queue.integer;
}

int main(void) {
    // proxima-devicesd is invoked with the standard streams backed by /dev/klog, which isn't a tty
    setvbuf(stdout, NULL, _IOLBF, 0);

    setup_hw_access();
    setup_events();
    acpi_init();

    if (daemon(1, 1)) {
        perror("devicesd: daemon failed");
        return EXIT_FAILURE;
    }

    serial_init_late();

    for (;;) {
        process_events(0);
    }
}

typedef struct {
    void (*func)(void *);
    void *ctx;
} task_t;

static task_t *tasks;
static size_t tasks_capacity;
static size_t tasks_head;
static size_t tasks_tail;
static size_t tasks_count;

bool queue_task(void (*func)(void *), void *ctx) {
    if (tasks_count >= tasks_capacity) {
        size_t new_cap = tasks_capacity ? tasks_capacity * 2 : 8;
        tasks = realloc(tasks, sizeof(*tasks) * new_cap);
        if (unlikely(!tasks)) return false;

        if (tasks_head != 0) {
            // count == cap and head != 0, so the occupied area wraps around. make it not do that.
            // there is guaranteed to be enough space available because we doubled the capacity.
            memcpy(&tasks[tasks_capacity], tasks, tasks_tail * sizeof(*tasks));
            tasks_tail = tasks_capacity + tasks_tail;
        }

        tasks_capacity = new_cap;
    }

    assert(tasks_count == 0 || tasks_head != tasks_tail);

    tasks[tasks_tail].func = func;
    tasks[tasks_tail].ctx = ctx;
    if (++tasks_tail == tasks_capacity) tasks_tail = 0;
    tasks_count += 1;

    return true;
}

static void handle_event(hydrogen_event_t *event) {
    switch (event->type) {
    case HYDROGEN_EVENT_INTERRUPT_PENDING: {
        if (disable_interrupts) break;

        for (;;) {
            irq_handler_t *handler = event->ctx;
            int error = hydrogen_interrupt_wait(handler->handle, 1, 0);

            if (error) {
                if (likely(error == EAGAIN)) return;
                fprintf(stderr, "devicesd: failed to get interrupt information: %s\n", strerror(error));
                exit(EXIT_FAILURE);
            }

            handler->func(handler);

            error = hydrogen_interrupt_complete(handler->handle);
            if (unlikely(error)) {
                fprintf(stderr, "devicesd: failed to complete interrupt: %s\n", strerror(error));
                exit(EXIT_FAILURE);
            }
        }

        break;
    }
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: serial_handle_readable(); break;
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: serial_handle_writable(); break;
    default:
        fprintf(stderr, "devicesd: unknown event type %d\n", event->type);
        exit(EXIT_FAILURE);
        break;
    }
}

bool process_events(uint64_t deadline) {
    bool did_work = false;

    // NOTE: uacpi_kernel_wait_for_work_completion relies on the native events to be done before the tasks.

    hydrogen_event_t buffer[128];

    for (;;) {
        hydrogen_ret_t ret = hydrogen_event_queue_wait(event_queue, buffer, sizeof(buffer) / sizeof(*buffer), deadline);

        if (ret.error) {
            if (likely(ret.error == EAGAIN)) break;
            fprintf(stderr, "devicesd: hydrogen_event_queue_wait failed: %s\n", strerror(ret.error));
            exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < ret.integer; i++) {
            handle_event(&buffer[i]);
        }

        did_work = true;
        if (ret.integer < sizeof(buffer) / sizeof(*buffer)) break;
        deadline = 1;
    }

    if (tasks_count != 0) {
        do {
            task_t *task = &tasks[tasks_head];
            if (++tasks_head == tasks_capacity) tasks_head = 0;
            tasks_count -= 1;
            task->func(task->ctx);
        } while (tasks_count != 0);

        did_work = true;
    }

    return did_work;
}
