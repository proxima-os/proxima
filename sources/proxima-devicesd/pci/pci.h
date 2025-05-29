#pragma once

#include "arch/mmio.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t segment;
    uint8_t bus;
    uint8_t device : 5;
    uint8_t function : 3;
} pci_address_t;

typedef struct {
    uintptr_t addr;
} pci_config_t;

void pci_init_acpi_tables(void);

bool pci_config_find(pci_config_t *out, pci_address_t address);

static inline uint8_t pci_read8(pci_config_t config, size_t offset) {
    return mmio_read8(config.addr, offset);
}

static inline uint16_t pci_read16(pci_config_t config, size_t offset) {
    return mmio_read16(config.addr, offset);
}

static inline uint32_t pci_read32(pci_config_t config, size_t offset) {
    return mmio_read32(config.addr, offset);
}

static inline void pci_write8(pci_config_t config, size_t offset, uint8_t value) {
    mmio_write8(config.addr, offset, value);
}

static inline void pci_write16(pci_config_t config, size_t offset, uint16_t value) {
    mmio_write16(config.addr, offset, value);
}

static inline void pci_write32(pci_config_t config, size_t offset, uint32_t value) {
    mmio_write32(config.addr, offset, value);
}
