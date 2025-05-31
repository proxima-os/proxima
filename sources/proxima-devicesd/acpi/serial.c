#include "serial.h"
#include "acpi/acpi.h"
#include "arch/pio.h"
#include "compiler.h"
#include "main.h"
#include <bits/posix/posix_string.h>
#include <errno.h>
#include <fcntl.h>
#include <hydrogen/eventqueue.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/ioctl-data.h>
#include <hydrogen/ioctl.h>
#include <hydrogen/types.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <uacpi/resources.h>
#include <unistd.h>

#define SERIAL_RHR 0
#define SERIAL_THR 0
#define SERIAL_IER 1
#define SERIAL_DLAB_LOW 0
#define SERIAL_DLAB_HIGH 1
#define SERIAL_IIR 2
#define SERIAL_FCR 2
#define SERIAL_LCR 3
#define SERIAL_MCR 4
#define SERIAL_LSR 5
#define SERIAL_MSR 6
#define SERIAL_SCRATCH 7

#define SERIAL_IER_HAVE_DATA (1u << 0)
#define SERIAL_IER_TX_EMPTY (1u << 1)
#define SERIAL_IER_RECEIVER_LINE_STATUS (1u << 2)
#define SERIAL_IER_MODEM_STATUS (1u << 3)

#define SERIAL_IIR_NO_PENDING (1u << 0)
#define SERIAL_IIR_TYPE_MASK (3u << 1)
#define SERIAL_IIR_TYPE_MODEM_STATUS (0u << 1)
#define SERIAL_IIR_TYPE_TX_EMPTY (1u << 1)
#define SERIAL_IIR_TYPE_HAVE_DATA (2u << 1)
#define SERIAL_IIR_TYPE_LINE_STATUS (3u << 1)

#define SERIAL_FCR_FIFO_ENABLE (1u << 0)
#define SERIAL_FCR_FIFO_CLEAR_RX (1u << 1)
#define SERIAL_FCR_FIFO_CLEAR_TX (1u << 2)
#define SERIAL_FCR_FIFO_CLEAR (SERIAL_FCR_FIFO_CLEAR_TX | SERIAL_FCR_FIFO_CLEAR_RX)
#define SERIAL_FCR_DMA_MODE (1u << 3)
#define SERIAL_FCR_IRQ_MASK (3u << 6)
#define SERIAL_FCR_IRQ_1 (0u << 6)
#define SERIAL_FCR_IRQ_4 (1u << 6)
#define SERIAL_FCR_IRQ_8 (2u << 6)
#define SERIAL_FCR_IRQ_14 (3u << 6)

#define SERIAL_LCR_DATA_MASK (3u << 0)
#define SERIAL_LCR_DATA_5BIT (0u << 0)
#define SERIAL_LCR_DATA_6BIT (1u << 0)
#define SERIAL_LCR_DATA_7BIT (2u << 0)
#define SERIAL_LCR_DATA_8BIT (3u << 0)
#define SERIAL_LCR_STOP_MASK (1u << 2)
#define SERIAL_LCR_STOP_1BIT (0u << 2)
#define SERIAL_LCR_STOP_2BIT (1u << 2)
#define SERIAL_LCR_PARITY_MASK (7u << 3)
#define SERIAL_LCR_PARITY_NONE (0u << 3)
#define SERIAL_LCR_PARITY_ODD (1u << 3)
#define SERIAL_LCR_PARITY_EVEN (3u << 3)
#define SERIAL_LCR_PARITY_MARK (5u << 3)
#define SERIAL_LCR_PARITY_SPACE (7u << 3)
#define SERIAL_LCR_BREAK (1u << 6)
#define SERIAL_LCR_DLAB (1u << 7)

#define SERIAL_LCR_PROTOCOL (SERIAL_LCR_PARITY_NONE | SERIAL_LCR_STOP_1BIT | SERIAL_LCR_DATA_8BIT)

#define SERIAL_MCR_DTR (1u << 0)
#define SERIAL_MCR_RTS (1u << 1)
#define SERIAL_MCR_IRQ (1u << 3)
#define SERIAL_MCR_LOOPBACK (1u << 4)

#define SERIAL_LSR_DR (1u << 0)
#define SERIAL_LSR_THRE (1u << 5)

#define SERIAL_FIFO_SIZE 16

static uint32_t serial_irq;
static pio_addr_t serial_io;
static unsigned serial_thr_available;
static int serial_pty_fd = -1;
static bool serial_readable;
static bool serial_writable;

static unsigned char *serial_input_buf;
static size_t serial_input_buf_head;
static size_t serial_input_buf_tail;
static bool serial_input_buf_data;
static size_t serial_input_buf_cap;

static bool read_listen, write_listen;

static inline uint8_t serial_read(uint8_t reg) {
    return pio_read8(serial_io + reg);
}

static inline void serial_write(uint8_t reg, uint8_t value) {
    pio_write8(serial_io + reg, value);
}

static void append_input(unsigned char value) {
    if (!serial_input_buf_cap || (serial_input_buf_data && serial_input_buf_head == serial_input_buf_tail)) {
        size_t new_cap = serial_input_buf_cap ? serial_input_buf_cap * 2 : 128;
        serial_input_buf = realloc(serial_input_buf, new_cap);
        if (unlikely(!serial_input_buf)) {
            fprintf(stderr, "devicesd: failed to allocate serial input buffer\n");
            exit(EXIT_FAILURE);
        }

        if (serial_input_buf_data && serial_input_buf_head >= serial_input_buf_tail) {
            memcpy(&serial_input_buf[serial_input_buf_cap], serial_input_buf, serial_input_buf_tail);
            serial_input_buf_tail += serial_input_buf_cap;
        }

        serial_input_buf_cap = new_cap;
    }

    serial_input_buf[serial_input_buf_tail++] = value;
    if (serial_input_buf_tail == serial_input_buf_cap) serial_input_buf_tail = 0;
    serial_input_buf_data = true;
}

static void listen_readable(void) {
    if (read_listen) return;

    int error = hydrogen_event_queue_add(
        event_queue,
        serial_pty_fd,
        HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE,
        0,
        NULL,
        0
    );
    if (unlikely(error)) {
        fprintf(stderr, "devicesd: failed to start listening to pseudoterminal readability: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }

    read_listen = true;
}

static void handle_serial_irq(irq_handler_t *ptr) {
    (void)ptr;

    uint8_t status = serial_read(SERIAL_IIR);
    if (status & SERIAL_IIR_NO_PENDING) return;

    switch (status & SERIAL_IIR_TYPE_MASK) {
    case SERIAL_IIR_TYPE_TX_EMPTY:
        if (serial_readable) {
            do {
                serial_thr_available = SERIAL_FIFO_SIZE;
                if (!serial_readable) break;
                serial_handle_readable();
            } while (serial_read(SERIAL_LSR) & SERIAL_LSR_THRE);

            if (!serial_thr_available) return;
        } else {
            serial_thr_available = SERIAL_FIFO_SIZE;
        }

        listen_readable();
        break;
    case SERIAL_IIR_TYPE_HAVE_DATA: {
        do {
            append_input(serial_read(SERIAL_RHR));
        } while (serial_read(SERIAL_LSR) & SERIAL_LSR_DR);

        if (serial_writable) {
            serial_handle_writable();
            if (!serial_input_buf_data) return;
        }

        if (write_listen) return;

        int error = hydrogen_event_queue_add(
            event_queue,
            serial_pty_fd,
            HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE,
            0,
            NULL,
            0
        );
        if (unlikely(error)) {
            fprintf(stderr, "devicesd: failed to start listening to pseudoterminal writability: %s\n", strerror(error));
            exit(EXIT_FAILURE);
        }

        write_listen = true;

        break;
    }
    default:
        fprintf(stderr, "devicesd: unknown interrupt type %#x\n", status & SERIAL_IIR_TYPE_MASK);
        exit(EXIT_FAILURE);
        break;
    }
}

void serial_handle_readable(void) {
    if (!serial_thr_available) {
        serial_readable = true;

        hydrogen_ret_t
            ret = hydrogen_event_queue_remove(event_queue, serial_pty_fd, HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE, 0);
        if (unlikely(ret.error)) {
            fprintf(
                stderr,
                "devicesd: failed to stop listening to pseudoterminal readability: %s\n",
                strerror(ret.error)
            );
            exit(EXIT_FAILURE);
        }

        read_listen = false;
        return;
    }

    do {
        unsigned char data[SERIAL_FIFO_SIZE];
        ssize_t count = read(serial_pty_fd, data, sizeof(data));

        if (count <= 0) {
            if (errno == EAGAIN) {
                serial_readable = false;
                return;
            }

            perror("devicesd: failed to read from serial pty");
            exit(EXIT_FAILURE);
        }

        for (ssize_t i = 0; i < count; i++) {
            serial_write(SERIAL_THR, data[i]);
        }

        serial_thr_available -= count;
    } while (serial_thr_available);
}

void serial_handle_writable(void) {
    if (!serial_input_buf_data) {
        serial_writable = true;

        hydrogen_ret_t
            ret = hydrogen_event_queue_remove(event_queue, serial_pty_fd, HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE, 0);
        if (unlikely(ret.error)) {
            fprintf(
                stderr,
                "devicesd: failed to stop listening to pseudoterminal writability: %s\n",
                strerror(ret.error)
            );
            exit(EXIT_FAILURE);
        }

        write_listen = false;
        return;
    }

    for (;;) {
        size_t avail = serial_input_buf_head < serial_input_buf_tail ? serial_input_buf_tail - serial_input_buf_head
                                                                     : serial_input_buf_cap - serial_input_buf_head;

        ssize_t count = write(serial_pty_fd, &serial_input_buf[serial_input_buf_head], avail);
        if (count < 0) {
            if (errno == EAGAIN) {
                serial_writable = false;
                return;
            }

            perror("devicesd: failed to write to pseudoterminal");
            exit(EXIT_FAILURE);
        }

        serial_input_buf_head += count;
        if (serial_input_buf_head == serial_input_buf_cap) serial_input_buf_head = 0;

        if (serial_input_buf_head == serial_input_buf_tail) {
            serial_input_buf_data = false;
            return;
        }
    }
}

static irq_handler_t serial_irq_handler = {.func = handle_serial_irq};

static uacpi_iteration_decision handle_resource(void *ctx, uacpi_resource *resource) {
    (void)ctx;

    switch (resource->type) {
    case UACPI_RESOURCE_TYPE_IRQ: serial_irq = resource->irq.irqs[0]; break;
    case UACPI_RESOURCE_TYPE_IO: serial_io = resource->io.minimum; break;
    }

    return UACPI_ITERATION_DECISION_CONTINUE;
}

static pthread_t serial_klog_thread;

uacpi_iteration_decision handle_serial(void *ctx, uacpi_namespace_node *node, uacpi_u32 depth) {
    (void)ctx;
    (void)depth;

    uacpi_resources *resources;
    uacpi_status status = uacpi_get_current_resources(node, &resources);
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to get serial resources: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    status = uacpi_for_each_resource(resources, handle_resource, NULL);
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to list serial resources: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    uacpi_free_resources(resources);

    printf("devicesd: serial io %#x, irq %u\n", serial_io, serial_irq);

    // 115200 baud
    serial_write(SERIAL_IER, 0);
    serial_write(SERIAL_LCR, SERIAL_LCR_DLAB | SERIAL_LCR_PROTOCOL);
    serial_write(SERIAL_DLAB_LOW, 0x01);
    serial_write(SERIAL_DLAB_HIGH, 0x00);
    serial_write(SERIAL_LCR, SERIAL_LCR_PROTOCOL);
    serial_write(SERIAL_FCR, SERIAL_FCR_IRQ_1 | SERIAL_FCR_FIFO_CLEAR | SERIAL_FCR_FIFO_ENABLE);
    serial_write(SERIAL_MCR, SERIAL_MCR_LOOPBACK | SERIAL_MCR_RTS | SERIAL_MCR_DTR);

    serial_write(SERIAL_THR, 0xae);
    if (serial_read(SERIAL_RHR) != 0xae) {
        fprintf(stderr, "devicesd: serial test failed\n");
        exit(1);
    }

    serial_write(SERIAL_MCR, SERIAL_MCR_IRQ | SERIAL_MCR_RTS | SERIAL_MCR_DTR);

    hydrogen_ioctl_irq_open_t data = {.irq = serial_irq, .flags = HYDROGEN_HANDLE_CLONE_KEEP};
    hydrogen_ret_t ret = hydrogen_fs_ioctl(i8259_fd, __IOCTL_IRQ_OPEN, &data, sizeof(data));
    if (unlikely(ret.error)) {
        fprintf(stderr, "devicesd: failed to open serial port irq: %s\n", strerror(ret.error));
        exit(EXIT_FAILURE);
    }
    serial_irq_handler.handle = ret.integer;

    int error = hydrogen_event_queue_add(
        event_queue,
        ret.integer,
        HYDROGEN_EVENT_INTERRUPT_PENDING,
        0,
        &serial_irq_handler,
        0
    );
    if (unlikely(error)) {
        fprintf(stderr, "devicesd: failed to start listening to serial port irq: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }

    serial_pty_fd = posix_openpt(O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (serial_pty_fd < 0) {
        perror("devicesd: posix_openpt failed");
        exit(EXIT_FAILURE);
    }

    if (grantpt(serial_pty_fd)) {
        perror("devicesd: grantpt failed");
        exit(EXIT_FAILURE);
    }

    if (unlockpt(serial_pty_fd)) {
        perror("devicesd: unlockpt failed");
        exit(EXIT_FAILURE);
    }

    listen_readable();
    serial_write(SERIAL_IER, SERIAL_IER_TX_EMPTY | SERIAL_IER_HAVE_DATA);

    const char *name = ptsname(serial_pty_fd);
    if (unlikely(!name)) {
        perror("devicesd: ptsname failed");
        exit(EXIT_FAILURE);
    }

    if (name) {
        if (symlink(name, "/dev/console")) {
            perror("devicesd: failed to create /dev/console");
        }
    } else {
        perror("devicesd: ptsname failed");
    }

    return UACPI_ITERATION_DECISION_BREAK;
}

static void *serial_klog_thread_func(void *ctx) {
    // NOTE: All of our own code assumes we're single-threaded, so this must only call OS code.

    int src_fd = open("/dev/klog", O_RDONLY);
    if (unlikely(src_fd < 0)) {
        perror("devicesd: failed to open /dev/klog");
        exit(EXIT_FAILURE);
    }

    int dst_fd = open(ctx, O_WRONLY | O_NOCTTY);
    if (unlikely(dst_fd < 0)) {
        perror("devicesd: failed to open serial console");
        exit(EXIT_FAILURE);
    }

    free(ctx);

    for (;;) {
        unsigned char buffer[4096];
        ssize_t count = read(src_fd, buffer, sizeof(buffer));

        if (unlikely(count <= 0)) {
            perror("devicesd: failed to read from /dev/klog");
            exit(EXIT_FAILURE);
        }

        ssize_t index = 0;

        do {
            ssize_t cur = write(dst_fd, buffer + index, count - index);

            if (unlikely(count <= 0)) {
                perror("devicesd: failed to write to serial console");
                exit(EXIT_FAILURE);
            }

            index += cur;
        } while (index < count);
    }
}

void serial_init_late(void) {
    const char *name = ptsname(serial_pty_fd);
    if (unlikely(!name)) {
        perror("devicesd: ptsname failed");
        exit(EXIT_FAILURE);
    }

    char *copied_name = strdup(name);
    if (unlikely(!copied_name)) {
        perror("devicesd: strdup failed");
        exit(EXIT_FAILURE);
    }

    int error = pthread_create(&serial_klog_thread, NULL, serial_klog_thread_func, copied_name);
    if (unlikely(error)) {
        fprintf(stderr, "devicesd: failed to create klog mirroring thread: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }
}
