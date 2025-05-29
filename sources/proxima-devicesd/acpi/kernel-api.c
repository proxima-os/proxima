#include "kernel-api.h"
#include "acpi/acpi.h"
#include "arch/pio.h"
#include "compiler.h"
#include "main.h"
#include "pci/pci.h"
#include <assert.h>
#include <errno.h>
#include <hydrogen/eventqueue.h>
#include <hydrogen/handle.h>
#include <hydrogen/interrupt.h>
#include <hydrogen/ioctl-data.h>
#include <hydrogen/ioctl.h>
#include <hydrogen/memory.h>
#include <hydrogen/thread.h>
#include <hydrogen/time.h>
#include <hydrogen/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <uacpi/kernel_api.h>

uint64_t rsdp_phys;

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address) {
    *out_rsdp_address = rsdp_phys;
    return UACPI_STATUS_OK;
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    uacpi_phys_addr offset = addr & (hydrogen_page_size - 1);
    addr &= ~(hydrogen_page_size - 1);
    len = (len + offset + (hydrogen_page_size - 1)) & ~(hydrogen_page_size - 1);

    void *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, addr);
    return ptr != MAP_FAILED ? ptr + offset : NULL;
}

void uacpi_kernel_unmap(void *addr, uacpi_size len) {
    uacpi_phys_addr offset = (uintptr_t)addr & (hydrogen_page_size - 1);
    addr -= offset;
    len = (len + offset + (hydrogen_page_size - 1)) & ~(hydrogen_page_size - 1);
    munmap(addr, len);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *format, ...) {
    va_list args;
    va_start(args, format);
    uacpi_kernel_vlog(level, format, args);
    va_end(args);
}

void uacpi_kernel_vlog(uacpi_log_level level, const uacpi_char *format, uacpi_va_list args) {
    static const char *names[] = {
        [UACPI_LOG_DEBUG] = "debug",
        [UACPI_LOG_TRACE] = "trace",
        [UACPI_LOG_INFO] = "info",
        [UACPI_LOG_WARN] = "warn",
        [UACPI_LOG_ERROR] = "error",
    };

    fprintf(stderr, "devicesd: [uacpi %s] ", names[level]);
    vfprintf(stderr, format, args);
}

// TODO: Use MCFG instead of legacy access mechanism.

_Static_assert(sizeof(pci_config_t) <= sizeof(uacpi_handle), "pci_config_t too large");

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address address, uacpi_handle *out_handle) {
    pci_address_t addr = {address.segment, address.bus, address.device, address.function};
    pci_config_t config;
    if (unlikely(!pci_config_find(&config, addr))) return UACPI_STATUS_NOT_FOUND;

    memcpy(out_handle, &config, sizeof(config));
    return UACPI_STATUS_OK;
}

void uacpi_kernel_pci_device_close(uacpi_handle handle) {
    (void)handle;
}

uacpi_status uacpi_kernel_pci_read8(uacpi_handle device, uacpi_size offset, uacpi_u8 *value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    *value = pci_read8(config, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read16(uacpi_handle device, uacpi_size offset, uacpi_u16 *value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    *value = pci_read16(config, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read32(uacpi_handle device, uacpi_size offset, uacpi_u32 *value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    *value = pci_read32(config, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write8(uacpi_handle device, uacpi_size offset, uacpi_u8 value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    pci_write8(config, offset, value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write16(uacpi_handle device, uacpi_size offset, uacpi_u16 value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    pci_write16(config, offset, value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write32(uacpi_handle device, uacpi_size offset, uacpi_u32 value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    pci_write32(config, offset, value);
    return UACPI_STATUS_OK;
}

#if ARCH_HAS_PIO
_Static_assert(sizeof(uacpi_handle) >= sizeof(pio_addr_t), "pio_addr_t too large");

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle) {
    if (base + len > ARCH_PIO_MAX) return UACPI_STATUS_NOT_FOUND;

    pio_addr_t addr = base;
    memcpy(out_handle, &addr, sizeof(addr));
    return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(uacpi_handle handle) {
    (void)handle;
}

uacpi_status uacpi_kernel_io_read8(uacpi_handle handle, uacpi_size offset, uacpi_u8 *out_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    *out_value = pio_read8(addr + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read16(uacpi_handle handle, uacpi_size offset, uacpi_u16 *out_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    *out_value = pio_read16(addr + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read32(uacpi_handle handle, uacpi_size offset, uacpi_u32 *out_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    *out_value = pio_read32(addr + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write8(uacpi_handle handle, uacpi_size offset, uacpi_u8 in_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    pio_write8(addr + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write16(uacpi_handle handle, uacpi_size offset, uacpi_u16 in_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    pio_write16(addr + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write32(uacpi_handle handle, uacpi_size offset, uacpi_u32 in_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    pio_write32(addr + offset, in_value);
    return UACPI_STATUS_OK;
}
#else
uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle) {
    (void)base;
    (void)len;
    (void)out_handle;
    return UACPI_STATUS_UNIMPLEMENTED;
}

void uacpi_kernel_io_unmap(uacpi_handle handle) {
    (void)handle;
}

uacpi_status uacpi_kernel_io_read8(uacpi_handle handle, uacpi_size offset, uacpi_u8 *out_value) {
    (void)handle;
    (void)offset;
    (void)out_value;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_io_read16(uacpi_handle handle, uacpi_size offset, uacpi_u16 *out_value) {
    (void)handle;
    (void)offset;
    (void)out_value;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_io_read32(uacpi_handle handle, uacpi_size offset, uacpi_u32 *out_value) {
    (void)handle;
    (void)offset;
    (void)out_value;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_io_write8(uacpi_handle handle, uacpi_size offset, uacpi_u8 in_value) {
    (void)handle;
    (void)offset;
    (void)in_value;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_io_write16(uacpi_handle handle, uacpi_size offset, uacpi_u16 in_value) {
    (void)handle;
    (void)offset;
    (void)in_value;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_io_write32(uacpi_handle handle, uacpi_size offset, uacpi_u32 in_value) {
    (void)handle;
    (void)offset;
    (void)in_value;
    return UACPI_STATUS_UNIMPLEMENTED;
}
#endif

#define HUGE_SIZE 0x1000

struct free_obj {
    struct free_obj *next;
};

#define MIN_ALLOC_SIZE ((sizeof(struct free_obj) + (_Alignof(max_align_t) - 1)) & ~(_Alignof(max_align_t) - 1))

#define BUCKET(x) ((sizeof(unsigned long) * 8) - __builtin_clzl((x) - 1))

static struct free_obj *buckets[BUCKET(HUGE_SIZE - 1) + 1];

void *uacpi_kernel_alloc(uacpi_size size) {
    if (unlikely(size == 0)) return (void *)_Alignof(max_align_t);

    if (unlikely(size >= HUGE_SIZE)) {
        size = (size + (hydrogen_page_size - 1)) & ~(hydrogen_page_size - 1);

        void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
        if (unlikely(ptr == MAP_FAILED)) return UACPI_NULL;
        return ptr;
    }

    if (unlikely(size < MIN_ALLOC_SIZE)) size = MIN_ALLOC_SIZE;

    unsigned bucket = BUCKET(size);
    struct free_obj *obj = buckets[bucket];

    if (likely(obj)) {
        buckets[bucket] = obj->next;
        return obj;
    }

    void *ptr = mmap(NULL, HUGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
    if (unlikely(ptr == MAP_FAILED)) return UACPI_NULL;

    obj = ptr;
    struct free_obj *last = ptr;
    size = 1ul << bucket;

    for (size_t offset = size; offset < HUGE_SIZE; offset += size) {
        struct free_obj *cur = ptr + offset;
        last->next = cur;
        last = cur;
    }

    buckets[bucket] = obj->next;
    return obj;
}

void *uacpi_kernel_alloc_zeroed(uacpi_size size) {
    void *ptr = uacpi_kernel_alloc(size);
    if (unlikely(ptr == UACPI_NULL)) return UACPI_NULL;

    if (likely(size < HUGE_SIZE)) memset(ptr, 0, size);
    return ptr;
}

void uacpi_kernel_free(void *mem, uacpi_size size) {
    if (unlikely(!mem)) return;
    if (unlikely(size == 0)) return;

    if (unlikely(size >= HUGE_SIZE)) {
        size = (size + (hydrogen_page_size - 1)) & ~(hydrogen_page_size - 1);
        munmap(mem, size);
        return;
    }

    if (unlikely(size < MIN_ALLOC_SIZE)) size = MIN_ALLOC_SIZE;

    unsigned bucket = BUCKET(size);
    struct free_obj *obj = mem;

    obj->next = buckets[bucket];
    buckets[bucket] = obj;
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) {
    return hydrogen_boot_time();
}

void uacpi_kernel_stall(uacpi_u8 usec) {
    uacpi_u64 end = uacpi_kernel_get_nanoseconds_since_boot() + usec * 1000ull;
    while (uacpi_kernel_get_nanoseconds_since_boot() < end);
}

void uacpi_kernel_sleep(uacpi_u64 msec) {
    uacpi_u64 end = hydrogen_boot_time() + msec * 1000000ull;
    int error;

    do {
        error = hydrogen_thread_sleep(end);
    } while (error != 0);
}

typedef struct {
    bool locked;
} mutex_t;

uacpi_handle uacpi_kernel_create_mutex(void) {
    return uacpi_kernel_alloc_zeroed(sizeof(mutex_t));
}

void uacpi_kernel_free_mutex(uacpi_handle handle) {
    uacpi_kernel_free(handle, sizeof(mutex_t));
}

typedef struct {
    size_t count;
} event_t;

uacpi_handle uacpi_kernel_create_event(void) {
    return uacpi_kernel_alloc_zeroed(sizeof(event_t));
}

void uacpi_kernel_free_event(uacpi_handle handle) {
    uacpi_kernel_free(handle, sizeof(event_t));
}

uacpi_thread_id uacpi_kernel_get_thread_id(void) {
    return (uacpi_thread_id)1; // We are single-threaded.
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout) {
    // Unlike spinlocks, mutexes are exposed to AML and so must actually do locking even though we are single-threaded.
    // We don't have to use atomics, though.

    mutex_t *mutex = handle;

    if (likely(!mutex->locked)) {
        mutex->locked = true;
        return UACPI_STATUS_OK;
    }

    if (likely(timeout != 0)) {
        uint64_t deadline = 0;
        if (timeout != 0xffff) deadline = hydrogen_boot_time() + timeout * 1000000ull;

        while (process_events(deadline)) {
            if (!mutex->locked) {
                mutex->locked = true;
                return UACPI_STATUS_OK;
            }
        }
    }

    return UACPI_STATUS_TIMEOUT;
}

void uacpi_kernel_release_mutex(uacpi_handle handle) {
    mutex_t *mutex = handle;
    mutex->locked = false;
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout) {
    // Just like mutexes, events are exposed to AML and must not be no-ops despite devicesd being single-threaded.

    event_t *event = handle;

    if (likely(event->count > 0)) {
        event->count -= 1;
        return UACPI_TRUE;
    }

    if (likely(timeout != 0)) {
        uint64_t deadline = 0;
        if (timeout != 0xffff) deadline = hydrogen_boot_time() + timeout * 1000000ull;

        while (process_events(deadline)) {
            if (event->count > 0) {
                event->count -= 1;
                return UACPI_TRUE;
            }
        }
    }

    return UACPI_FALSE;
}

void uacpi_kernel_signal_event(uacpi_handle handle) {
    event_t *event = handle;
    event->count += 1;
}

void uacpi_kernel_reset_event(uacpi_handle handle) {
    event_t *event = handle;
    event->count = 0;
}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *req) {
    switch (req->type) {
    case UACPI_FIRMWARE_REQUEST_TYPE_BREAKPOINT: fprintf(stderr, "devicesd: firmware breakpoint\n"); break;
    case UACPI_FIRMWARE_REQUEST_TYPE_FATAL:
        fprintf(
            stderr,
            "devicesd: fatal firmware error (type: %#x, code: %#x, arg: %#" PRIx64 ")\n",
            req->fatal.type,
            req->fatal.code,
            req->fatal.arg
        );
        exit(EXIT_FAILURE);
        break;
    default:
        fprintf(stderr, "devicesd: unknown firmware request type %d\n", req->type);
        exit(EXIT_FAILURE);
        break;
    }

    return UACPI_STATUS_OK;
}

typedef struct {
    irq_handler_t base;
    uacpi_interrupt_handler handler;
    uacpi_handle ctx;
} uacpi_interrupt_t;

static bool handle_uacpi_interrupt(irq_handler_t *ptr) {
    uacpi_interrupt_t *self = (uacpi_interrupt_t *)ptr;
    return self->handler(self->ctx) == UACPI_INTERRUPT_HANDLED;
}

uacpi_status uacpi_kernel_install_interrupt_handler(
    uacpi_u32 irq,
    uacpi_interrupt_handler handler,
    uacpi_handle ctx,
    uacpi_handle *out_irq_handle
) {
    uacpi_interrupt_t *data = uacpi_kernel_alloc_zeroed(sizeof(*data));
    if (unlikely(!data)) return UACPI_STATUS_OUT_OF_MEMORY;

    hydrogen_ioctl_irq_open_t args = {.irq = irq, .active_low = true, .level_triggered = true};
    data->base.handle = ioctl(isa_irq_fd >= 0 ? isa_irq_fd : gsi_fd, __IOCTL_IRQ_OPEN, &args);
    if (unlikely(data->base.handle < 0)) {
        uacpi_kernel_free(data, sizeof(*data));
        return os_to_acpi_error(errno);
    }

    data->base.func = handle_uacpi_interrupt;
    data->handler = handler;
    data->ctx = ctx;

    int error = hydrogen_event_queue_add(
        event_queue,
        data->base.handle,
        HYDROGEN_EVENT_INTERRUPT_PENDING,
        0,
        &data->base,
        0
    );
    if (unlikely(error)) {
        hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, data->base.handle);
        uacpi_kernel_free(data, sizeof(*data));
        return os_to_acpi_error(error);
    }

    *out_irq_handle = data;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(uacpi_interrupt_handler handler, uacpi_handle irq_handle) {
    (void)handler;

    uacpi_interrupt_t *data = irq_handle;

    assert(data->handler == handler);

    hydrogen_ret_t
        ret = hydrogen_event_queue_remove(event_queue, data->base.handle, HYDROGEN_EVENT_INTERRUPT_PENDING, 0);
    if (unlikely(ret.error)) return os_to_acpi_error(ret.error);
    assert(ret.pointer == data);

    hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, data->base.handle);
    uacpi_kernel_free(data, sizeof(*data));

    return UACPI_STATUS_OK;
}

// Spinlocks are no-ops in release mode because we're singlethreaded

uacpi_handle uacpi_kernel_create_spinlock(void) {
    static char dummy;
    return &dummy;
}

void uacpi_kernel_free_spinlock(uacpi_handle handle) {
    (void)handle;
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle) {
    (void)handle;

#ifndef NDEBUG
    assert(*(char *)handle == 0);
    *(char *)handle = 1;
#endif

    return 0;
}

void uacpi_kernel_unlock_spinlock(uacpi_handle handle, uacpi_cpu_flags flags) {
    (void)handle;
    (void)flags;

#ifndef NDEBUG
    assert(*(char *)handle == 1);
    *(char *)handle = 0;
#endif
}

uacpi_status uacpi_kernel_schedule_work(uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx) {
    (void)type;

    if (unlikely(!queue_task(handler, ctx))) return UACPI_STATUS_OUT_OF_MEMORY;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    process_events(1);
    return UACPI_STATUS_OK;
}
