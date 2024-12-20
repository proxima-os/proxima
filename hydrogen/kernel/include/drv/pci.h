#ifndef HYDROGEN_DRV_PCI_H
#define HYDROGEN_DRV_PCI_H

#include <stdint.h>

typedef struct {
    uint16_t segment;
    uint8_t bus;
    uint8_t device;
    uint8_t function;
} pci_address_t;

typedef struct {
    volatile void *ptr;
} pci_config_t;

void init_pci_access(void);

int get_pci_config(pci_config_t *out, pci_address_t address);

uint8_t pci_readb(pci_config_t config, unsigned offset);

uint16_t pci_readw(pci_config_t config, unsigned offset);

uint32_t pci_readl(pci_config_t config, unsigned offset);

void pci_writeb(pci_config_t config, unsigned offset, uint8_t value);

void pci_writew(pci_config_t config, unsigned offset, uint16_t value);

void pci_writel(pci_config_t config, unsigned offset, uint32_t value);

#endif // HYDROGEN_DRV_PCI_H
