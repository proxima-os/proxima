#ifndef HYDROGEN_DRV_PCI_H
#define HYDROGEN_DRV_PCI_H

#include <stdint.h>

typedef struct {
    uint16_t segment;
    uint8_t bus;
    uint8_t device;
    uint8_t function;
} pci_address_t;

void init_pci_access(void);

int get_pci_config(uintptr_t *out, pci_address_t address);

uint8_t pci_readb(uintptr_t config, unsigned offset);

uint16_t pci_readw(uintptr_t config, unsigned offset);

uint32_t pci_readl(uintptr_t config, unsigned offset);

void pci_writeb(uintptr_t config, unsigned offset, uint8_t value);

void pci_writew(uintptr_t config, unsigned offset, uint16_t value);

void pci_writel(uintptr_t config, unsigned offset, uint32_t value);

#endif // HYDROGEN_DRV_PCI_H
