#include "drv/acpi.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "asm/pio.h"
#include "compiler.h"
#include "drv/pci.h"
#include "drv/pic.h"
#include "limine.h"
#include "mem/heap.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "sched/sched.h"
#include "sched/sema.h"
#include "string.h"
#include "uacpi/event.h"
#include "uacpi/kernel_api.h"
#include "uacpi/platform/arch_helpers.h"
#include "uacpi/platform/types.h"
#include "uacpi/status.h"
#include "uacpi/types.h"
#include "uacpi/uacpi.h"
#include "uacpi/utilities.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

#define EARLY_TABLE_BUF_SIZE 4096
#define MAX_DEFER_COUNT 256

static uint64_t rsdp_addr;

static struct {
    uacpi_work_handler handler;
    uacpi_handle ctx;
} defers[MAX_DEFER_COUNT];
static size_t defer_head;
static size_t defer_tail;
static semaphore_t defer_sema;

static size_t pending_work;
static list_t work_waiters;

// Must be called with IRQs disabled
static void register_work_start(void) {
    pending_work += 1;
}

static void register_work_end(void) {
    if (__atomic_fetch_sub(&pending_work, 1, __ATOMIC_ACQ_REL) != 1) return;

    irq_state_t state = save_disable_irq();

    // check again, an irq may have increased it
    // nothing special has to be done if that happened, since whatever increased it will call register_work_end too

    if (pending_work == 0) {
        disable_preempt();

        task_t *task = node_to_obj(task_t, node, work_waiters.first);

        while (task != NULL) {
            task_t *next = node_to_obj(task_t, node, task->node.next);
            sched_start(task);
            task = next;
        }

        list_clear(&work_waiters);
        enable_preempt();
    }

    restore_irq(state);
}

static void defer_executor_task(UNUSED void *ctx) {
    for (;;) {
        sema_wait(&defer_sema, 0);

        irq_state_t state = save_disable_irq();
        size_t idx = defer_head++;
        defer_head %= MAX_DEFER_COUNT;
        restore_irq(state);

        defers[idx].handler(defers[idx].ctx);
        register_work_end();
    }
}

void init_acpi_tables(void) {
    static LIMINE_REQ struct limine_rsdp_request rsdp_req = {.id = LIMINE_RSDP_REQUEST};
    if (!rsdp_req.response) panic("no response to rsdp request");
    rsdp_addr = rsdp_req.response->address;

    void *buf = vmalloc(EARLY_TABLE_BUF_SIZE);
    if (!buf) panic("failed to allocate buffer for early table access");

    uacpi_status ret = uacpi_setup_early_table_access(buf, EARLY_TABLE_BUF_SIZE);
    if (uacpi_unlikely_error(ret)) panic("failed to set up early table access: %s", uacpi_status_to_string(ret));
}

void init_acpi_fully(void) {
    task_t *task;
    int error = create_thread(&task, defer_executor_task, NULL);
    if (error) panic("failed to create deferred work executor (%d)", error);
    task_deref(task);

    uacpi_status ret = uacpi_initialize(0);
    if (uacpi_unlikely_error(ret)) panic("uacpi: failed to initialize: %s", uacpi_status_to_string(ret));

    ret = uacpi_namespace_load();
    if (uacpi_unlikely_error(ret)) panic("uacpi: failed to load namespace: %s", uacpi_status_to_string(ret));

    ret = uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC);
    if (uacpi_unlikely_error(ret)) panic("uacpi: failed to set interrupt model: %s", uacpi_status_to_string(ret));

    ret = uacpi_namespace_initialize();
    if (uacpi_unlikely_error(ret)) panic("uacpi: failed to init namespace: %s", uacpi_status_to_string(ret));

    ret = uacpi_finalize_gpe_initialization();
    if (uacpi_unlikely_error(ret)) panic("uacpi: failed to finalize init: %s", uacpi_status_to_string(ret));
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address) {
    *out_rsdp_address = rsdp_addr;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_raw_memory_read(uacpi_phys_addr address, uacpi_u8 byte_width, uacpi_u64 *out_value) {
    uintptr_t addr;
    int error = kvmm_map_mmio(&addr, addr, byte_width, PMAP_WRITE, CACHE_WRITEBACK);
    uacpi_status status;

    if (error == 0) {
        status = UACPI_STATUS_OK;

        switch (byte_width) {
        case 1: *out_value = *(volatile uint8_t *)phys_to_virt(address); break;
        case 2: *out_value = *(volatile uint16_t *)phys_to_virt(address); break;
        case 4: *out_value = *(volatile uint32_t *)phys_to_virt(address); break;
        case 8: *out_value = *(volatile uint64_t *)phys_to_virt(address); break;
        default: status = UACPI_STATUS_INVALID_ARGUMENT; break;
        }

        kvmm_unmap_mmio(addr, byte_width);
    } else {
        status = UACPI_STATUS_OUT_OF_MEMORY;
    }

    return status;
}

uacpi_status uacpi_kernel_raw_memory_write(uacpi_phys_addr address, uacpi_u8 byte_width, uacpi_u64 in_value) {
    uintptr_t addr;
    int error = kvmm_map_mmio(&addr, addr, byte_width, PMAP_WRITE, CACHE_WRITEBACK);
    uacpi_status status;

    if (error == 0) {
        status = UACPI_STATUS_OK;

        switch (byte_width) {
        case 1: *(volatile uint8_t *)phys_to_virt(address) = in_value; break;
        case 2: *(volatile uint16_t *)phys_to_virt(address) = in_value; break;
        case 4: *(volatile uint32_t *)phys_to_virt(address) = in_value; break;
        case 8: *(volatile uint64_t *)phys_to_virt(address) = in_value; break;
        default: status = UACPI_STATUS_INVALID_ARGUMENT; break;
        }

        kvmm_unmap_mmio(addr, byte_width);
    } else {
        status = UACPI_STATUS_OUT_OF_MEMORY;
    }

    return status;
}

uacpi_status uacpi_kernel_raw_io_read(uacpi_io_addr address, uacpi_u8 byte_width, uacpi_u64 *out_value) {
    switch (byte_width) {
    case 1: *out_value = inb(address); return UACPI_STATUS_OK;
    case 2: *out_value = inw(address); return UACPI_STATUS_OK;
    case 4: *out_value = inl(address); return UACPI_STATUS_OK;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }
}

uacpi_status uacpi_kernel_raw_io_write(uacpi_io_addr address, uacpi_u8 byte_width, uacpi_u64 in_value) {
    switch (byte_width) {
    case 1: outb(address, in_value); return UACPI_STATUS_OK;
    case 2: outw(address, in_value); return UACPI_STATUS_OK;
    case 4: outl(address, in_value); return UACPI_STATUS_OK;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }
}

uacpi_status uacpi_kernel_pci_read(
        uacpi_pci_address *address,
        uacpi_size offset,
        uacpi_u8 byte_width,
        uacpi_u64 *value
) {
    pci_config_t config;
    int error = get_pci_config(
            &config,
            (pci_address_t){address->segment, address->bus, address->device, address->function}
    );
    if (error) return UACPI_STATUS_NOT_FOUND;

    switch (byte_width) {
    case 1: *value = pci_readb(config, offset); break;
    case 2: *value = pci_readw(config, offset); break;
    case 4: *value = pci_readl(config, offset); break;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write(
        uacpi_pci_address *address,
        uacpi_size offset,
        uacpi_u8 byte_width,
        uacpi_u64 value
) {
    pci_config_t config;
    int error = get_pci_config(
            &config,
            (pci_address_t){address->segment, address->bus, address->device, address->function}
    );
    if (error) return UACPI_STATUS_NOT_FOUND;

    switch (byte_width) {
    case 1: pci_writeb(config, offset, value); break;
    case 2: pci_writew(config, offset, value); break;
    case 4: pci_writel(config, offset, value); break;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, UNUSED uacpi_size len, uacpi_handle *out_handle) {
    *out_handle = (uacpi_handle)base;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(UNUSED uacpi_handle handle) {
}

uacpi_status uacpi_kernel_io_read(uacpi_handle handle, uacpi_size offset, uacpi_u8 byte_width, uacpi_u64 *value) {
    return uacpi_kernel_raw_io_read((uacpi_io_addr)handle + offset, byte_width, value);
}

uacpi_status uacpi_kernel_io_write(uacpi_handle handle, uacpi_size offset, uacpi_u8 byte_width, uacpi_u64 value) {
    return uacpi_kernel_raw_io_write((uacpi_io_addr)handle + offset, byte_width, value);
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    uintptr_t vaddr;
    int error = kvmm_map_mmio(&vaddr, addr, len, PMAP_WRITE, CACHE_WRITEBACK);
    return error == 0 ? (void *)vaddr : NULL;
}

void uacpi_kernel_unmap(void *addr, uacpi_size len) {
    kvmm_unmap_mmio((uintptr_t)addr, len);
}

typedef struct {
    size_t size;
} alloc_meta_t;

#define META_OFFSET ((sizeof(alloc_meta_t) + (_Alignof(max_align_t) - 1)) & ~(_Alignof(max_align_t) - 1))

void *uacpi_kernel_alloc(uacpi_size size) {
    if (size == 0) return (void *)META_OFFSET;
    size += META_OFFSET;

    void *ptr = vmalloc(size);

    if (ptr != NULL) {
        ((alloc_meta_t *)ptr)->size = size;
        return ptr + META_OFFSET;
    } else {
        return NULL;
    }
}

void *uacpi_kernel_calloc(uacpi_size count, uacpi_size size) {
    void *ptr = uacpi_kernel_alloc(count * size);
    if (ptr) memset(ptr, 0, count * size);
    return ptr;
}

void uacpi_kernel_free(void *mem) {
    if (mem == NULL || mem == (void *)META_OFFSET) return;

    alloc_meta_t *meta = mem - META_OFFSET;
    vmfree(meta, meta->size);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *str) {
    const char *lstr;

    switch (level) {
    case UACPI_LOG_DEBUG: lstr = "debug"; break;
    case UACPI_LOG_TRACE: lstr = "trace"; break;
    case UACPI_LOG_INFO: lstr = "info"; break;
    case UACPI_LOG_WARN: lstr = "warn"; break;
    case UACPI_LOG_ERROR: lstr = "error"; break;
    }

    printk("uacpi: %s: %s", lstr, str);
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) {
    return timeconv_apply(tsc2ns_conv, read_time());
}

void uacpi_kernel_stall(uacpi_u8 usec) {
    uint64_t tsc = read_time() + timeconv_apply(ns2tsc_conv, usec * 1000);
    while (read_time() < tsc) cpu_relax();
}

void uacpi_kernel_sleep(uacpi_u64 msec) {
    sched_stop(read_time() + timeconv_apply(ns2tsc_conv, msec * 1000000));
}

uacpi_handle uacpi_kernel_create_mutex(void) {
    mutex_t *mutex = vmalloc(sizeof(*mutex));
    if (mutex) memset(mutex, 0, sizeof(*mutex));
    return mutex;
}

void uacpi_kernel_free_mutex(uacpi_handle handle) {
    vmfree(handle, sizeof(mutex_t));
}

uacpi_handle uacpi_kernel_create_event(void) {
    semaphore_t *sema = vmalloc(sizeof(*sema));
    if (sema) memset(sema, 0, sizeof(*sema));
    return sema;
}

void uacpi_kernel_free_event(uacpi_handle handle) {
    vmfree(handle, sizeof(semaphore_t));
}

uacpi_thread_id uacpi_kernel_get_thread_id(void) {
    return current_task;
}

static uint64_t get_real_timeout(uint16_t timeout) {
    if (timeout != 0xffff) {
        return read_time() + timeconv_apply(ns2tsc_conv, timeout * 1000000);
    } else {
        return 0;
    }
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout) {
    bool success = timeout == 0 ? mutex_try_lock(handle) : mutex_lock_timeout(handle, get_real_timeout(timeout));
    return success ? UACPI_STATUS_OK : UACPI_STATUS_TIMEOUT;
}

void uacpi_kernel_release_mutex(uacpi_handle handle) {
    mutex_unlock(handle);
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout) {
    return sema_wait(handle, get_real_timeout(timeout)) ? UACPI_TRUE : UACPI_FALSE;
}

void uacpi_kernel_signal_event(uacpi_handle handle) {
    sema_signal(handle);
}

void uacpi_kernel_reset_event(uacpi_handle handle) {
    sema_reset(handle);
}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *req) {
    switch (req->type) {
    case UACPI_FIRMWARE_REQUEST_TYPE_BREAKPOINT: return UACPI_STATUS_OK;
    case UACPI_FIRMWARE_REQUEST_TYPE_FATAL:
        panic("acpi: AML reported fatal error: %u, %u, %U", req->fatal.type, req->fatal.code, req->fatal.arg);
        break;
    default: return UACPI_STATUS_UNIMPLEMENTED;
    }
}

typedef struct {
    uacpi_interrupt_handler handler;
    uacpi_handle ctx;
    uint32_t irq;
    int vector;
} acpi_irq_ctx_t;

static void acpi_irq_handler(void *ptr) {
    acpi_irq_ctx_t *ctx = ptr;

    register_work_start();
    ctx->handler(ctx->ctx);
    register_work_end();
}

uacpi_status uacpi_kernel_install_interrupt_handler(
        uacpi_u32 irq,
        uacpi_interrupt_handler handler,
        uacpi_handle ctx,
        uacpi_handle *out_irq_handle
) {
    acpi_irq_ctx_t *context = vmalloc(sizeof(*context));
    if (!context) {
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    context->handler = handler;
    context->ctx = ctx;
    context->irq = irq;

    int vector = alloc_irq_vectors(1, 1);
    if (vector < 0) {
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    context->vector = vector;

    pic_install_vector(vector, acpi_irq_handler, context);
    pic_setup_isa(irq, vector);

    *out_irq_handle = context;

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(UNUSED uacpi_interrupt_handler handler, uacpi_handle irq_handle) {
    acpi_irq_ctx_t *ctx = irq_handle;
    ASSERT(ctx->handler == handler);

    pic_reset_isa(ctx->irq);
    pic_uninstall_vector(ctx->vector, acpi_irq_handler);
    free_irq_vectors(ctx->vector, 1);
    vmfree(ctx, sizeof(*ctx));

    return UACPI_STATUS_OK;
}

uacpi_handle uacpi_kernel_create_spinlock(void) {
    return vmalloc(0);
}

void uacpi_kernel_free_spinlock(uacpi_handle handle) {
    vmfree(handle, 0);
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(UNUSED uacpi_handle handle) {
    return save_disable_irq();
}

void uacpi_kernel_unlock_spinlock(UNUSED uacpi_handle handle, uacpi_cpu_flags flags) {
    restore_irq(flags);
}

uacpi_status uacpi_kernel_schedule_work(UNUSED uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx) {
    irq_state_t state = save_disable_irq();

    size_t idx = defer_tail;
    size_t next_tail = (idx + 1) % MAX_DEFER_COUNT;

    if (next_tail == defer_head) {
        restore_irq(state);
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    defer_tail = next_tail;

    defers[idx].handler = handler;
    defers[idx].ctx = ctx;
    register_work_start();

    restore_irq(state);
    sema_signal(&defer_sema);

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    if (__atomic_load_n(&pending_work, __ATOMIC_ACQUIRE) == 0) {
        return UACPI_STATUS_OK;
    }

    irq_state_t state = save_disable_irq();

    if (pending_work != 0) {
        list_insert_tail(&work_waiters, &current_task->node);
        sched_stop(0);
    }

    restore_irq(state);
    return UACPI_STATUS_OK;
}
