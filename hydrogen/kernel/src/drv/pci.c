#include "drv/pci.h"
#include "hydrogen/error.h"
#include "mem/heap.h"
#include "mem/kvmm.h"
#include "mem/vheap.h"
#include "string.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

typedef struct {
    volatile void *ptr;
    uint16_t segment;
    uint8_t min_bus;
    uint8_t max_bus;
} config_range_t;

static config_range_t *config_ranges;
static size_t num_config_ranges;

void init_pci_access(void) {
    struct uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) {
        printk("pci: could not find mcfg table: %s\n", uacpi_status_to_string(status));
        return;
    }

    struct acpi_mcfg *mcfg = table.ptr;
    num_config_ranges = (mcfg->hdr.length - sizeof(*mcfg)) / sizeof(mcfg->entries[0]);

    config_ranges = vmalloc(num_config_ranges * sizeof(*config_ranges));
    if (!config_ranges) panic("pci: failed to allocate config range info");
    memset(config_ranges, 0, num_config_ranges * sizeof(*config_ranges));

    for (size_t i = 0; i < num_config_ranges; i++) {
        struct acpi_mcfg_allocation *alloc = &mcfg->entries[i];

        uintptr_t addr;
        int error = kvmm_map_mmio(
                &addr,
                alloc->address + ((uintptr_t)alloc->start_bus << 20),
                (uintptr_t)(alloc->end_bus - alloc->start_bus) << 20,
                PMAP_WRITE,
                CACHE_NONE
        );
        if (error) panic("pci: failed to map config space (%d)", error);

        config_ranges[i].ptr = (volatile void *)addr;
        config_ranges[i].segment = alloc->segment;
        config_ranges[i].min_bus = alloc->start_bus;
        config_ranges[i].max_bus = alloc->end_bus;
    }

    uacpi_table_unref(&table);
}

int get_pci_config(pci_config_t *out, pci_address_t address) {
    ASSERT(!(address.device & ~0x1f));
    ASSERT(!(address.function & ~7));

    for (size_t i = 0; i < num_config_ranges; i++) {
        config_range_t *range = &config_ranges[i];

        if (range->segment == address.segment && range->min_bus <= address.bus && address.bus <= range->max_bus) {
            out->ptr = range->ptr + ((uintptr_t)address.device << 15) + ((uintptr_t)address.function << 12);
            return 0;
        }
    }

    return ERR_NOT_FOUND;
}

uint8_t pci_readb(pci_config_t config, unsigned offset) {
    ASSERT(offset < 4096);

    return *(volatile uint8_t *)(config.ptr + offset);
}

uint16_t pci_readw(pci_config_t config, unsigned offset) {
    ASSERT(offset < 4096);
    ASSERT((offset & 1) == 0);

    return *(volatile uint16_t *)(config.ptr + offset);
}

uint32_t pci_readl(pci_config_t config, unsigned offset) {
    ASSERT(offset < 4096);
    ASSERT((offset & 3) == 0);

    return *(volatile uint32_t *)(config.ptr + offset);
}

void pci_writeb(pci_config_t config, unsigned offset, uint8_t value) {
    ASSERT(offset < 4096);

    *(volatile uint8_t *)(config.ptr + offset) = value;
}

void pci_writew(pci_config_t config, unsigned offset, uint16_t value) {
    ASSERT(offset < 4096);
    ASSERT((offset & 1) == 0);

    *(volatile uint16_t *)(config.ptr + offset) = value;
}

void pci_writel(pci_config_t config, unsigned offset, uint32_t value) {
    ASSERT(offset < 4096);
    ASSERT((offset & 3) == 0);

    *(volatile uint32_t *)(config.ptr + offset) = value;
}
