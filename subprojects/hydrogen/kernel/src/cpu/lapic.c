#include "cpu/lapic.h"
#include "asm/cr.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "asm/mmio.h"
#include "asm/msr.h"
#include "proxima/compiler.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "cpu/xsave.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/vheap.h"
#include "sched/sched.h"
#include "string.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/time.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

static uintptr_t xapic_regs;
static bool using_x2apic;

extern void start_ap(struct limine_mp_info *);

#define LAPIC_ID 0x20
#define LAPIC_EOI 0xb0
#define LAPIC_SPR 0xf0
#define LAPIC_SPR_ENABLE 0x100
#define LAPIC_ERR 0x280
#define LAPIC_ICR 0x300
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_LVT_LINT0 0x350
#define LAPIC_LVT_LINT1 0x360
#define LAPIC_LVT_ERROR 0x370
#define LAPIC_TIMER_ICR 0x380
#define LAPIC_TIMER_CCR 0x390
#define LAPIC_TIMER_DCR 0x3e0
#define LAPIC_TIMER_DCR_16 3

#define LAPIC_ICR_PENDING (1ul << 12)
#define LAPIC_ICR_ASSERT (1ul << 14)
#define LAPIC_ICR_BROADCAST (3ul << 18)

#define LAPIC_LVT_NMI (4u << 8)
#define LAPIC_LVT_ACTIVE_LOW (1u << 13)
#define LAPIC_LVT_LEVEL_TRIG (1u << 15)
#define LAPIC_LVT_MASKED 0x10000

static uint32_t lapic_read32(unsigned reg) {
    if (!using_x2apic) return mmio_read32(xapic_regs, reg);
    else return rdmsr(0x800 + (reg >> 4));
}

static void lapic_write32(unsigned reg, uint32_t value) {
    if (!using_x2apic) mmio_write32(xapic_regs, reg, value);
    else wrmsr(0x800 + (reg >> 4), value);
}

static void lapic_write64(unsigned reg, uint64_t value) {
    if (!using_x2apic) {
        mmio_write32(xapic_regs, reg + 0x10, value >> 32);
        mmio_write32(xapic_regs, reg, value);
    } else {
        wrmsr(0x800 + (reg >> 4), value);
    }
}

static void handle_apic_error(UNUSED idt_frame_t *frame) {
    lapic_write32(LAPIC_ERR, 0);
    panic("lapic error: 0x%x", lapic_read32(LAPIC_ERR));
}

static void do_init_lapic(struct acpi_madt *madt) {
    lapic_write32(LAPIC_SPR, IRQ_SPURIOUS);
    lapic_write32(LAPIC_ERR, 0);
    lapic_write32(LAPIC_LVT_TIMER, LAPIC_LVT_MASKED | IRQ_TIMER);
    lapic_write32(LAPIC_LVT_LINT0, LAPIC_LVT_MASKED | IRQ_SPURIOUS);
    lapic_write32(LAPIC_LVT_LINT1, LAPIC_LVT_MASKED | IRQ_SPURIOUS);
    lapic_write32(LAPIC_LVT_ERROR, IRQ_APIC_ERR);
    lapic_write32(LAPIC_TIMER_DCR, LAPIC_TIMER_DCR_16);
    lapic_write32(LAPIC_SPR, LAPIC_SPR_ENABLE | IRQ_SPURIOUS);
    write_cr8(0);

    uint32_t id = lapic_read32(LAPIC_ID);
    if (!using_x2apic) id >>= 24;
    if (current_cpu.apic_id != id) panic("lapic(%u): id in register doesn't match (%u)", current_cpu.acpi_id, id);

    current_cpu.apic_avail = true;

    struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

    for (struct acpi_entry_hdr *cur = madt->entries; cur < end; cur = (void *)cur + cur->length) {
        uint32_t id;
        uint16_t flags;
        uint8_t input;

        if (cur->type == ACPI_MADT_ENTRY_TYPE_LAPIC_NMI) {
            struct acpi_madt_lapic_nmi *entry = (void *)cur;

            id = entry->uid;
            if (id == 0xff) id = UINT32_MAX;
            flags = entry->flags;
            input = entry->lint;
        } else if (cur->type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC_NMI) {
            struct acpi_madt_x2apic_nmi *entry = (void *)cur;

            id = entry->uid;
            flags = entry->flags;
            input = entry->lint;
        } else {
            continue;
        }

        if (id != UINT32_MAX && id != current_cpu.acpi_id) continue;

        unsigned reg = input ? LAPIC_LVT_LINT1 : LAPIC_LVT_LINT0;
        uint32_t entry = LAPIC_LVT_NMI;

        if ((flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) entry |= LAPIC_LVT_ACTIVE_LOW;
        if ((flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) entry |= LAPIC_LVT_LEVEL_TRIG;

        lapic_write32(reg, entry);
    }
}

typedef struct {
    uintptr_t idle_stack;
    cpu_init_data_t init_data;
    struct acpi_madt *madt;
    bool basic_init_done;
} cpu_start_data_t;

_Noreturn void do_start_ap(cpu_start_data_t *data) {
    init_cpu(&data->init_data);
    init_sched_cpu();
    init_xsave_ap();
    do_init_lapic(data->madt);
    init_time_cpu();
    __atomic_store_n(&data->basic_init_done, true, __ATOMIC_RELEASE);

    printk("smp: cpu %U initialized\n", current_cpu.id);

    enable_irq();
    for (;;) cpu_idle();
}

static LIMINE_REQ struct limine_mp_request mp_req = {.id = LIMINE_MP_REQUEST, .flags = LIMINE_MP_X2APIC};

void init_lapic(void) {
    if (!mp_req.response) panic("no response to mp request");
    using_x2apic = mp_req.response->flags & LIMINE_MP_X2APIC;

    // Map xAPIC registers
    struct uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) panic("could not find madt: %s", uacpi_status_to_string(status));
    struct acpi_madt *madt = table.ptr;

    if (!using_x2apic) {
        uint64_t phys = madt->local_interrupt_controller_address;
        struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

        for (struct acpi_entry_hdr *cur = madt->entries; cur < end; cur = (void *)cur + cur->length) {
            if (cur->type == ACPI_MADT_ENTRY_TYPE_LAPIC_ADDRESS_OVERRIDE) {
                phys = ((struct acpi_madt_lapic_address_override *)cur)->address;
                break;
            }
        }

        int error = kvmm_map_mmio(&xapic_regs, phys, 0x1000, PMAP_WRITE, CACHE_NONE);
        if (error) panic("failed to map lapic regs (%d)", error);
    }

    // Find mp info for BSP
    struct limine_mp_info *bsp_info = NULL;

    for (uint64_t i = 0; i < mp_req.response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_req.response->cpus[i];

        if (cpu->lapic_id == mp_req.response->bsp_lapic_id) {
            bsp_info = cpu;
            break;
        }
    }

    if (bsp_info == NULL) panic("could not find cpu info for bsp");
    current_cpu.acpi_id = bsp_info->processor_id;
    current_cpu.apic_id = bsp_info->processor_id;

    if (current_cpu.acpi_id > 0xff) panic("bsp lapic is not addressable by ioapic");

    idt_install(IRQ_APIC_ERR, handle_apic_error);
    do_init_lapic(madt);

    uacpi_table_unref(&table);
}

void init_smp(void) {
    struct uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) panic("could not find madt: %s", uacpi_status_to_string(status));
    struct acpi_madt *madt = table.ptr;

    cpu_t *first = NULL;
    cpu_t *last = NULL;

    // Create start data
    for (uint64_t i = 0; i < mp_req.response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_req.response->cpus[i];
        if (cpu->lapic_id == current_cpu.apic_id) continue;

        cpu_start_data_t *data = vmalloc(sizeof(*data));
        if (!data) panic("failed to allocate start data for ap");
        memset(data, 0, sizeof(*data));

        void *stack = allocate_kernel_stack();
        if (!stack) panic("failed to allocate idle stack for ap");
        data->idle_stack = (uintptr_t)stack;

        stack = allocate_kernel_stack();
        if (!stack) panic("failed to allocate fatal stack for ap");
        data->init_data.tss.fatal_stack = (uintptr_t)stack;

        void *xsave = alloc_xsave();
        if (!xsave) panic("failed to allocate xsave area for ap idle task");

        data->init_data.cpu.id = num_cpus++;
        data->init_data.cpu.apic_id = cpu->lapic_id;
        data->init_data.cpu.acpi_id = cpu->processor_id;
        data->init_data.cpu.sched.idle.xsave_area = xsave;
        data->madt = madt;

        if (last) last->next = &data->init_data.cpu;
        else first = &data->init_data.cpu;
        last = &data->init_data.cpu;

        cpu->extra_argument = (uintptr_t)data;
    }

    current_cpu_ptr->next = first;

    atomic_thread_fence(memory_order_seq_cst);

    for (uint64_t i = 0; i < mp_req.response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_req.response->cpus[i];
        if (cpu->lapic_id == current_cpu.apic_id) continue;
        __atomic_store_n(&cpu->goto_address, start_ap, __ATOMIC_RELAXED);
    }

    atomic_thread_fence(memory_order_seq_cst);

    // Wait for APs to finish initializing
    for (uint64_t i = 0; i < mp_req.response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_req.response->cpus[i];
        if (cpu->lapic_id == current_cpu.apic_id) continue;

        cpu_start_data_t *data = (cpu_start_data_t *)cpu->extra_argument;
        while (!__atomic_load_n(&data->basic_init_done, __ATOMIC_ACQUIRE)) cpu_relax();
    }

    uacpi_table_unref(&table);
}

void lapic_eoi(void) {
    lapic_write32(LAPIC_EOI, 0);
}

void lapic_timcal_start(void) {
    lapic_write32(LAPIC_LVT_TIMER, LAPIC_LVT_MASKED | IRQ_TIMER);
    lapic_write32(LAPIC_TIMER_ICR, UINT32_MAX);
}

uint32_t lapic_timcal_read(void) {
    return UINT32_MAX - lapic_read32(LAPIC_TIMER_CCR);
}

void lapic_setup_timer(timer_mode_t mode) {
    lapic_write32(LAPIC_TIMER_ICR, 0);
    lapic_write32(LAPIC_LVT_TIMER, mode | IRQ_TIMER);
}

void lapic_arm_timer(uint32_t ticks) {
    lapic_write32(LAPIC_TIMER_ICR, ticks);
}

void lapic_send_ipi(cpu_t *cpu, uint8_t vector) {
    if (!current_cpu.apic_avail) return;

    uint64_t icr = vector | LAPIC_ICR_ASSERT;

    if (cpu) {
        icr |= (uint64_t)cpu->apic_id << (using_x2apic ? 32 : 56);
    } else {
        icr |= LAPIC_ICR_BROADCAST;
    }

    if (!using_x2apic) {
        irq_state_t state = save_disable_irq();
        lapic_write64(LAPIC_ICR, icr);
        while (lapic_read32(LAPIC_ICR) & LAPIC_ICR_PENDING) cpu_relax();
        restore_irq(state);
    } else {
        lapic_write64(LAPIC_ICR, icr);
    }
}
