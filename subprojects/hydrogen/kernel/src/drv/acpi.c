#include "drv/acpi.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "asm/pio.h"
#include "proxima/compiler.h"
#include "cpu/cpu.h"
#include "drv/pci.h"
#include "drv/pic.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/vheap.h"
#include "sched/mutex.h"
#include "sched/proc.h"
#include "sched/sched.h"
#include "sched/sema.h"
#include "string.h"
#include "sys/vdso.h"
#include "uacpi/event.h"
#include "uacpi/kernel_api.h"
#include "uacpi/platform/arch_helpers.h"
#include "uacpi/platform/types.h"
#include "uacpi/sleep.h"
#include "uacpi/status.h"
#include "uacpi/types.h"
#include "uacpi/uacpi.h"
#include "uacpi/utilities.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EARLY_TABLE_BUF_SIZE 4096

static uint64_t rsdp_addr;

typedef struct uacpi_work {
    list_node_t node;
    uacpi_work_handler handler;
    uacpi_handle ctx;
} uacpi_work_t;

static list_t deferred_work;
static semaphore_t defer_sema;
static mutex_t defer_lock;

static size_t pending_work;
static list_t work_waiters;
static spinlock_t work_lock;

static void register_work_start(void) {
    __atomic_fetch_add(&pending_work, 1, __ATOMIC_ACQ_REL);
}

static void register_work_end(void) {
    if (__atomic_fetch_sub(&pending_work, 1, __ATOMIC_ACQ_REL) == 1) {
        irq_state_t state = save_disable_irq();
        disable_preempt();
        spin_lock_noirq(&work_lock);

        task_t *task = node_to_obj(task_t, node, work_waiters.first);

        while (task != NULL) {
            task_t *next = node_to_obj(task_t, node, task->node.next);
            sched_start(task);
            task = next;
        }

        list_clear(&work_waiters);

        spin_unlock_noirq(&work_lock);
        enable_preempt();
        restore_irq(state);
    }
}

static void defer_executor_task(UNUSED void *ctx) {
    for (;;) {
        sema_wait(&defer_sema, 0);

        mutex_lock(&defer_lock);
        uacpi_work_t *work = node_to_obj(uacpi_work_t, node, list_remove_head(&deferred_work));
        mutex_unlock(&defer_lock);

        work->handler(work->ctx);
        register_work_end();
        vmfree(work, sizeof(*work));
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

static uacpi_interrupt_ret handle_power_button(UNUSED uacpi_handle ctx) {
    uint64_t time = read_time();

    for (int i = 3; i > 0; i--) {
        printk("\rshutting down in %d seconds...", i);
        time += tsc_freq;
        sched_stop(time, NULL);
    }

    printk("\nshutting down...\n");

    uacpi_status ret = uacpi_prepare_for_sleep_state(UACPI_SLEEP_STATE_S5);
    if (uacpi_unlikely_error(ret)) {
        printk("sleep preparation failed: %s\n", uacpi_status_to_string(ret));
        return UACPI_INTERRUPT_HANDLED;
    }

    irq_state_t state = save_disable_irq();
    ret = uacpi_enter_sleep_state(UACPI_SLEEP_STATE_S5);
    if (uacpi_unlikely_error(ret)) {
        printk("failed to enter sleep state: %s\n", uacpi_status_to_string(ret));
        restore_irq(state);
        return UACPI_INTERRUPT_HANDLED;
    }

    panic("shutdown failed");
}

void init_acpi_fully(void) {
    task_t *task;
    int error = create_thread(&task, defer_executor_task, NULL, boot_cpu);
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

    ret = uacpi_install_fixed_event_handler(UACPI_FIXED_EVENT_POWER_BUTTON, handle_power_button, NULL);
    if (uacpi_unlikely_error(ret)) {
        panic("uacpi: failed to install power button handler: %s", uacpi_status_to_string(ret));
    }
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address) {
    *out_rsdp_address = rsdp_addr;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address address, uacpi_handle *out_handle) {
    uintptr_t addr;
    int error = get_pci_config(&addr, (pci_address_t){address.segment, address.bus, address.device, address.function});
    if (error) return UACPI_STATUS_NOT_FOUND;

    *out_handle = (void *)addr;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_pci_device_close(UNUSED uacpi_handle handle) {
}

uacpi_status uacpi_kernel_pci_read(uacpi_handle handle, uacpi_size offset, uacpi_u8 byte_width, uacpi_u64 *value) {
    switch (byte_width) {
    case 1: *value = pci_readb((uintptr_t)handle, offset); break;
    case 2: *value = pci_readw((uintptr_t)handle, offset); break;
    case 4: *value = pci_readl((uintptr_t)handle, offset); break;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write(uacpi_handle handle, uacpi_size offset, uacpi_u8 byte_width, uacpi_u64 value) {
    switch (byte_width) {
    case 1: pci_writeb((uintptr_t)handle, offset, value); break;
    case 2: pci_writew((uintptr_t)handle, offset, value); break;
    case 4: pci_writel((uintptr_t)handle, offset, value); break;
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
    switch (byte_width) {
    case 1: *value = inb((uintptr_t)handle + offset); return UACPI_STATUS_OK;
    case 2: *value = inw((uintptr_t)handle + offset); return UACPI_STATUS_OK;
    case 4: *value = inl((uintptr_t)handle + offset); return UACPI_STATUS_OK;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }
}

uacpi_status uacpi_kernel_io_write(uacpi_handle handle, uacpi_size offset, uacpi_u8 byte_width, uacpi_u64 value) {
    switch (byte_width) {
    case 1: outb((uintptr_t)handle + offset, value); return UACPI_STATUS_OK;
    case 2: outw((uintptr_t)handle + offset, value); return UACPI_STATUS_OK;
    case 4: outl((uintptr_t)handle + offset, value); return UACPI_STATUS_OK;
    default: return UACPI_STATUS_INVALID_ARGUMENT;
    }
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    uintptr_t vaddr;
    int error = kvmm_map_mmio(&vaddr, addr, len, PMAP_WRITE, CACHE_WRITEBACK);
    return error == 0 ? (void *)vaddr : NULL;
}

void uacpi_kernel_unmap(void *addr, uacpi_size len) {
    kvmm_unmap_mmio((uintptr_t)addr, len);
}

void *uacpi_kernel_alloc(uacpi_size size) {
    return vmalloc(size);
}

void uacpi_kernel_free(void *mem, size_t size) {
    vmfree(mem, size);
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
    sched_stop(read_time() + timeconv_apply(ns2tsc_conv, msec * 1000000), NULL);
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
    bool success = timeout != 0 ? sema_wait(handle, get_real_timeout(timeout)) : sema_try_wait(handle);
    return success ? UACPI_TRUE : UACPI_FALSE;
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

    semaphore_t sema;
    task_t *dispatcher;
    size_t count;
} acpi_irq_ctx_t;

static void acpi_irq_dispatcher(void *ptr) {
    acpi_irq_ctx_t *ctx = ptr;

    for (;;) {
        sema_wait(&ctx->sema, 0);
        if (__atomic_fetch_sub(&ctx->count, 1, __ATOMIC_ACQ_REL) == 0) break;

        ctx->handler(ctx->ctx);
        register_work_end();
    }
}

static void acpi_irq_handler(void *ptr) {
    acpi_irq_ctx_t *ctx = ptr;
    register_work_start();
    __atomic_fetch_add(&ctx->count, 1, __ATOMIC_ACQUIRE);
    sema_signal(&ctx->sema);
}

uacpi_status uacpi_kernel_install_interrupt_handler(
        uacpi_u32 irq,
        uacpi_interrupt_handler handler,
        uacpi_handle ctx,
        uacpi_handle *out_irq_handle
) {
    acpi_irq_ctx_t *context = vmalloc(sizeof(*context));
    if (!context) return UACPI_STATUS_OUT_OF_MEMORY;
    memset(context, 0, sizeof(*context));

    context->handler = handler;
    context->ctx = ctx;
    context->irq = irq;

    int vector = alloc_irq_vectors(1, 1);
    if (vector < 0) {
        vmfree(context, sizeof(*context));
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    context->vector = vector;

    int error = create_thread(&context->dispatcher, acpi_irq_dispatcher, context, boot_cpu);
    if (error) {
        free_irq_vectors(vector, 1);
        vmfree(context, sizeof(*context));
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

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

    sema_signal(&ctx->sema); // if the sema is signaled without incrementing count, the dispatcher will terminate
    sched_wait(ctx->dispatcher, 0);

    task_deref(ctx->dispatcher);
    vmfree(ctx, sizeof(*ctx));

    return UACPI_STATUS_OK;
}

uacpi_handle uacpi_kernel_create_spinlock(void) {
    spinlock_t *lock = vmalloc(sizeof(*lock));
    if (lock) memset(lock, 0, sizeof(*lock));
    return lock;
}

void uacpi_kernel_free_spinlock(uacpi_handle handle) {
    vmfree(handle, sizeof(spinlock_t));
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle) {
    return spin_lock(handle);
}

void uacpi_kernel_unlock_spinlock(UNUSED uacpi_handle handle, uacpi_cpu_flags flags) {
    spin_unlock(handle, flags);
}

uacpi_status uacpi_kernel_schedule_work(UNUSED uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx) {
    uacpi_work_t *work = vmalloc(sizeof(*work));
    if (!work) return UACPI_STATUS_OUT_OF_MEMORY;
    work->handler = handler;
    work->ctx = ctx;

    mutex_lock(&defer_lock);
    list_insert_tail(&deferred_work, &work->node);
    mutex_unlock(&defer_lock);

    register_work_start();
    sema_signal(&defer_sema);

    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    irq_state_t state = spin_lock(&work_lock);

    if (__atomic_load_n(&pending_work, __ATOMIC_ACQUIRE) != 0) {
        list_insert_tail(&work_waiters, &current_task->node);
        sched_stop(0, &work_lock);
    }

    spin_unlock(&work_lock, state);
    return UACPI_STATUS_OK;
}
