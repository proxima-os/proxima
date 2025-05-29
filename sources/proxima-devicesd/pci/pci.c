#include "pci.h"
#include "acpi/acpi.h"
#include "compiler.h"
#include "main.h"
#include <hydrogen/filesystem.h>
#include <hydrogen/memory.h>
#include <hydrogen/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

typedef struct {
    uint16_t segment;
    uint8_t bus_min;
    uint8_t bus_max;
    uintptr_t virt;
} ecam_range_t;

static ecam_range_t *ecam_ranges;
static size_t num_ecam_ranges;

void pci_init_acpi_tables(void) {
    uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to find mcfg table: %s\n", acpi_error_string(status));
        return;
    }

    struct acpi_mcfg *mcfg = table.ptr;
    num_ecam_ranges = (mcfg->hdr.length - offsetof(struct acpi_mcfg, entries)) / sizeof(*mcfg->entries);
    ecam_ranges = calloc(num_ecam_ranges, sizeof(*ecam_ranges));
    if (unlikely(!ecam_ranges)) {
        num_ecam_ranges = 0;
        fprintf(stderr, "devicesd: failed to allocate ecam range list\n");
        return;
    }

    for (size_t i = 0; i < num_ecam_ranges; i++) {
        ecam_range_t *range = &ecam_ranges[i];
        range->segment = mcfg->entries[i].segment;
        range->bus_min = mcfg->entries[i].start_bus;
        range->bus_max = mcfg->entries[i].end_bus;

        if (range->bus_min <= range->bus_max) {
            uint64_t phys = mcfg->entries[i].address + ((uint64_t)range->bus_min << 20);
            size_t size = (size_t)(range->bus_max - range->bus_min + 1) << 20;

            hydrogen_ret_t ret = hydrogen_fs_mmap(
                mem_fd,
                HYDROGEN_THIS_VMM,
                0,
                size,
                HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_SHARED |
                    HYDROGEN_MEM_TYPE_DEVICE_NO_COMBINE_REORDER_EARLY,
                phys
            );

            if (ret.error) {
                free(ecam_ranges);
                num_ecam_ranges = 0;
                fprintf(stderr, "devicesd: failed to map ecam range: %s\n", strerror(ret.error));
                return;
            }

            range->virt = ret.integer;
        }
    }
}

bool pci_config_find(pci_config_t *out, pci_address_t address) {
    for (size_t i = 0; i < num_ecam_ranges; i++) {
        ecam_range_t *range = &ecam_ranges[i];

        if (range->segment == address.segment && range->bus_min <= address.bus && address.bus <= range->bus_max) {
            out->addr = range->virt + ((size_t)(address.bus - range->bus_min) << 20);
            out->addr |= (size_t)(address.device << 15);
            out->addr |= (size_t)(address.function << 12);
            return true;
        }
    }

    return false;
}
