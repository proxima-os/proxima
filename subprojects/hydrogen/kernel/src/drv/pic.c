#include "drv/pic.h"
#include "asm/irq.h"
#include "asm/mmio.h"
#include "asm/pio.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "cpu/lapic.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/vheap.h"
#include "sched/mutex.h"
#include "sched/sched.h"
#include "string.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/print.h"
#include "util/spinlock.h"
#include <stdint.h>

typedef struct {
    list_node_t node;
    uintptr_t regs;
    uint32_t id;
    uint32_t gsi_base;
    uint32_t num_irqs;
    spinlock_t lock;
} ioapic_t;

static list_t ioapics;

static ioapic_t *get_ioapic_for_gsi(uint32_t gsi) {
    list_foreach(ioapics, ioapic_t, node, cur) {
        if (cur->gsi_base <= gsi && gsi - cur->gsi_base < cur->num_irqs) {
            return cur;
        }
    }

    return NULL;
}

#define IOAPICVER 1
#define IOREDTBL(i) (0x10 + (i) * 2)

#define IOAPIC_MASKED 0x10000

static uint32_t ioapic_read(ioapic_t *apic, unsigned reg) {
    mmio_write32(apic->regs, 0, reg);
    return mmio_read32(apic->regs, 0x10);
}

static void ioapic_write(ioapic_t *apic, unsigned reg, uint32_t value) {
    mmio_write32(apic->regs, 0, reg);
    mmio_write32(apic->regs, 0x10, value);
}

static struct {
    uint32_t gsi;
    uint16_t flags;
} isa_irq_info[16];

static struct {
    void (*func)(void *);
    void *ctx;
} dev_irq_handlers[IRQ_DEV_MAX - IRQ_DEV_MIN];

static void handle_dev_irq(idt_frame_t *frame) {
    disable_preempt();

    if (dev_irq_handlers[frame->vector - IRQ_DEV_MIN].func) {
        dev_irq_handlers[frame->vector - IRQ_DEV_MIN].func(dev_irq_handlers[frame->vector - IRQ_DEV_MIN].ctx);
    } else {
        panic("unhandled device irq on vector %U", frame->vector);
    }

    lapic_eoi();
    enable_preempt();
}

void init_pic(void) {
    for (int i = IRQ_DEV_MIN; i <= IRQ_DEV_MAX; i++) {
        idt_install(i, handle_dev_irq);
    }

    struct uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) panic("failed to find madt: %s", uacpi_status_to_string(status));

    struct acpi_madt *madt = table.ptr;
    struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

    if (madt->flags & ACPI_PCAT_COMPAT) {
        outb(0x20, 0x11);
        outb(0xa0, 0x11);
        outb(0x21, 0xf8);
        outb(0xa1, 0xf8);
        outb(0x21, 4);
        outb(0xa1, 2);
        outb(0x21, 1);
        outb(0xa1, 1);
        outb(0x21, 0xff);
        outb(0xa1, 0xff);
    }

    for (unsigned i = 0; i < 16; i++) {
        isa_irq_info[i].gsi = i;
    }

    for (struct acpi_entry_hdr *cur = madt->entries; cur < end; cur = (void *)cur + cur->length) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
            struct acpi_madt_ioapic *entry = (void *)cur;

            ioapic_t *apic = vmalloc(sizeof(*apic));
            if (!apic) panic("failed to allocate ioapic data");
            memset(apic, 0, sizeof(*apic));

            int error = kvmm_map_mmio(&apic->regs, entry->address, 12, PMAP_WRITE, CACHE_NONE);
            if (error) panic("failed to map ioapic regs (%d)", error);

            apic->id = entry->id;
            apic->gsi_base = entry->gsi_base;
            apic->num_irqs = ((ioapic_read(apic, IOAPICVER) >> 16) & 0xff) + 1;

            list_insert_tail(&ioapics, &apic->node);

            printk("pic: i/o apic %u has %u irqs starting at %u\n", apic->id, apic->num_irqs, apic->gsi_base);

            for (unsigned i = 0; i < apic->num_irqs; i++) {
                ioapic_write(apic, IOREDTBL(i), IOAPIC_MASKED | IRQ_SPURIOUS);
                ioapic_write(apic, IOREDTBL(i) + 1, boot_cpu->apic_id << 24);
            }
        } else if (cur->type == ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
            struct acpi_madt_interrupt_source_override *entry = (void *)cur;
            if (entry->bus != 0) continue;

            isa_irq_info[entry->source].gsi = entry->gsi;
            isa_irq_info[entry->source].flags = entry->flags;
        }
    }

    for (struct acpi_entry_hdr *cur = madt->entries; cur < end; cur = (void *)cur + cur->length) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_NMI_SOURCE) {
            struct acpi_madt_nmi_source *entry = (void *)cur;
            uint32_t flags = PIC_NMI;

            if ((entry->flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) flags |= PIC_ACTIVE_LOW;
            if ((entry->flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) flags |= PIC_LEVEL_TRIG;

            pic_setup_irq(entry->gsi, 0, flags);
        }
    }

    uacpi_table_unref(&table);
}

void pic_setup_isa(uint32_t irq, uint32_t vector) {
    uint32_t flags = 0;
    uint16_t madtf = isa_irq_info[irq].flags;

    if ((madtf & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) flags |= PIC_ACTIVE_LOW;
    if ((madtf & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) flags |= PIC_LEVEL_TRIG;

    pic_setup_irq(isa_irq_info[irq].gsi, vector, flags);
}

void pic_setup_irq(uint32_t irq, uint32_t vector, uint32_t flags) {
    ioapic_t *apic = get_ioapic_for_gsi(irq);
    if (apic == NULL) panic("no i/o apic for gsi %u", irq);
    uint32_t i = irq - apic->gsi_base;

    irq_state_t state = spin_lock(&apic->lock);

    if ((ioapic_read(apic, IOREDTBL(i)) & IOAPIC_MASKED) == 0) panic("tried to set up gsi %u twice", irq);
    ioapic_write(apic, IOREDTBL(i), vector | flags);

    spin_unlock(&apic->lock, state);
}

void pic_reset_isa(uint32_t irq) {
    pic_reset_irq(isa_irq_info[irq].gsi);
}

void pic_reset_irq(uint32_t irq) {
    ioapic_t *apic = get_ioapic_for_gsi(irq);
    if (apic == NULL) panic("no i/o apic for gsi %u", irq);
    uint32_t i = irq - apic->gsi_base;

    irq_state_t state = spin_lock(&apic->lock);

    if (ioapic_read(apic, IOREDTBL(i)) & IOAPIC_MASKED) panic("tried to reset gsi %u twice", irq);
    ioapic_write(apic, IOREDTBL(i), IOAPIC_MASKED);

    spin_unlock(&apic->lock, state);
}

#define NUM_IRQ_VECS (IRQ_DEV_MAX - IRQ_DEV_MIN)

static uint32_t vector_usage[(NUM_IRQ_VECS + 31) / 32];
static mutex_t vectors_lock;

int alloc_irq_vectors(uint32_t count, uint32_t align) {
    if (count == 0) return IRQ_DEV_MIN;

    mutex_lock(&vectors_lock);

    int vector = (IRQ_DEV_MIN + (align - 1)) & ~(align - 1);

    while (vector + count <= IRQ_DEV_MAX) {
        uint32_t offset;
        for (offset = 0; offset < count; offset++) {
            int index = vector + offset - IRQ_DEV_MIN;
            if (vector_usage[index / 32] & (1u << (index % 32))) break;
        }

        if (offset == count) {
            for (offset = 0; offset < count; offset++) {
                int index = vector + offset - IRQ_DEV_MIN;
                vector_usage[index / 32] |= 1u << (index % 32);
            }

            mutex_unlock(&vectors_lock);
            return vector;
        }

        vector += offset + 1;
        vector = (vector + (align - 1)) & ~(align - 1);
    }

    mutex_unlock(&vectors_lock);
    return -1;
}

void free_irq_vectors(int base, uint32_t count) {
    if (base == -1 || count == 0) return;

    base -= IRQ_DEV_MIN;
    mutex_lock(&vectors_lock);

    while (count > 0) {
        vector_usage[base / 32] &= ~(1u << (base % 32));
        base++;
        count--;
    }

    mutex_unlock(&vectors_lock);
}

void pic_install_vector(int vector, void (*handler)(void *), void *ctx) {
    ASSERT(handler != NULL);

    if (dev_irq_handlers[vector - IRQ_DEV_MIN].func) panic("tried to override device irq handler for %d", vector);
    dev_irq_handlers[vector - IRQ_DEV_MIN].func = handler;
    dev_irq_handlers[vector - IRQ_DEV_MIN].ctx = ctx;
}

void pic_uninstall_vector(int vector, void (*handler)(void *)) {
    ASSERT(handler != NULL);

    if (dev_irq_handlers[vector - IRQ_DEV_MIN].func != handler) panic("tried to uninstall wrong vector (%d)", vector);
    dev_irq_handlers[vector - IRQ_DEV_MIN].func = NULL;
}
