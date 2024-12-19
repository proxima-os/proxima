#include "cpu/lapic.h"
#include "asm/idle.h"
#include "asm/msr.h"
#include "compiler.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "limine.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/panic.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

uint32_t cpu_apic_id;
uint32_t cpu_acpi_id;

static volatile void *xapic_regs;
static bool using_x2apic;

extern void park_ap(struct limine_mp_info *);

#define LAPIC_ID 0x20
#define LAPIC_EOI 0xb0
#define LAPIC_SPR 0xf0
#define LAPIC_SPR_ENABLE 0x100
#define LAPIC_ERR 0x280
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_LVT_LINT0 0x350
#define LAPIC_LVT_LINT1 0x360
#define LAPIC_LVT_ERROR 0x370
#define LAPIC_TIMER_ICR 0x380
#define LAPIC_TIMER_CCR 0x390
#define LAPIC_TIMER_DCR 0x3e0
#define LAPIC_TIMER_DCR_16 3

#define LAPIC_LVT_NMI (4u << 8)
#define LAPIC_LVT_ACTIVE_LOW (1u << 13)
#define LAPIC_LVT_LEVEL_TRIG (1u << 15)
#define LAPIC_LVT_MASKED 0x10000

static uint32_t lapic_read32(unsigned reg) {
    if (!using_x2apic) return *(volatile uint32_t *)(xapic_regs + reg);
    else return rdmsr(0x800 + (reg >> 4));
}

static void lapic_write32(unsigned reg, uint32_t value) {
    if (!using_x2apic) *(volatile uint32_t *)(xapic_regs + reg) = value;
    else wrmsr(0x800 + (reg >> 4), value);
}

static void handle_apic_error(UNUSED idt_frame_t *frame) {
    lapic_write32(LAPIC_ERR, 0);
    panic("lapic error: 0x%x", lapic_read32(LAPIC_ERR));
}

static void do_init_lapic(void) {
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

        extend_hhdm(phys, 0x1000, CACHE_NONE);
        xapic_regs = phys_to_virt(phys);
    }

    lapic_write32(LAPIC_SPR, IRQ_SPURIOUS);
    lapic_write32(LAPIC_ERR, 0);
    lapic_write32(LAPIC_LVT_TIMER, LAPIC_LVT_MASKED | IRQ_TIMER);
    lapic_write32(LAPIC_LVT_LINT0, LAPIC_LVT_MASKED | IRQ_SPURIOUS);
    lapic_write32(LAPIC_LVT_LINT1, LAPIC_LVT_MASKED | IRQ_SPURIOUS);
    lapic_write32(LAPIC_LVT_ERROR, IRQ_APIC_ERR);
    lapic_write32(LAPIC_TIMER_DCR, LAPIC_TIMER_DCR_16);
    lapic_write32(LAPIC_SPR, LAPIC_SPR_ENABLE | IRQ_SPURIOUS);
    cpu_apic_id = lapic_read32(LAPIC_ID);

    if (cpu_apic_id > 0xff) panic("bsp lapic is not addressable by i/o apics");

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

        if (id != UINT32_MAX && id != cpu_acpi_id) continue;

        unsigned reg = input ? LAPIC_LVT_LINT1 : LAPIC_LVT_LINT0;
        uint32_t entry = LAPIC_LVT_NMI;

        if ((flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) entry |= LAPIC_LVT_ACTIVE_LOW;
        if ((flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) entry |= LAPIC_LVT_LEVEL_TRIG;

        lapic_write32(reg, entry);
    }

    uacpi_table_unref(&table);
}

void init_lapic(void) {
    static LIMINE_REQ struct limine_mp_request mp_req = {.id = LIMINE_MP_REQUEST, .flags = LIMINE_MP_X2APIC};
    if (!mp_req.response) panic("no response to mp request");

    // Park all additional processors to make them stop using bootloader reclaimable stack and page tables
    struct limine_mp_info *bsp_info = NULL;

    for (uint64_t i = 0; i < mp_req.response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_req.response->cpus[i];

        if (cpu->lapic_id == mp_req.response->bsp_lapic_id) {
            bsp_info = cpu;
            continue;
        }

        cpu->extra_argument = UINT64_MAX;
        __atomic_store_n(&cpu->goto_address, park_ap, __ATOMIC_SEQ_CST);
        while (__atomic_load_n(&cpu->extra_argument, __ATOMIC_SEQ_CST) != 0) cpu_relax();
    }

    atomic_thread_fence(memory_order_seq_cst);

    if (bsp_info == NULL) panic("could not find cpu info for bsp");
    cpu_acpi_id = bsp_info->processor_id;

    idt_install(IRQ_APIC_ERR, handle_apic_error);

    using_x2apic = mp_req.response->flags & LIMINE_MP_X2APIC;
    do_init_lapic();
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
