#include "drv/hpet.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/panic.h"
#include <stdint.h>

#define HPET_CAP 0x00
#define HPET_CNF 0x10
#define HPET_CNF_ENABLE (1u << 0)
#define HPET_CNT 0xf0
#define HPET_TN_CNF(i) (0x100 + (i) * 0x20)
#define HPET_TN_CNF_INT_ENB (1u << 2)

uint64_t hpet_period_fs;

static volatile void *hpet_regs;

static inline uint64_t hpet_read(unsigned offset) {
    return *(volatile uint64_t *)(hpet_regs + offset);
}

static inline void hpet_write(unsigned offset, uint64_t value) {
    *(volatile uint64_t *)(hpet_regs + offset) = value;
}

void init_hpet(void) {
    struct uacpi_table table;
    uacpi_status ret = uacpi_table_find_by_signature(ACPI_HPET_SIGNATURE, &table);
    if (uacpi_unlikely_error(ret)) panic("failed to find hpet table: %s", uacpi_status_to_string(ret));

    struct acpi_hpet *hpet = table.ptr;
    if (hpet->address.address_space_id != ACPI_AS_ID_SYS_MEM) panic("incorrect hpet address space");
    extend_hhdm(hpet->address.address, 1024, CACHE_NONE);
    hpet_regs = phys_to_virt(hpet->address.address);

    uacpi_table_unref(&table);

    uint64_t cap = hpet_read(HPET_CAP);
    hpet_period_fs = cap >> 32;

    for (unsigned i = 0; i <= ((cap >> 8) & 0x1f); i++) {
        hpet_write(HPET_TN_CNF(i), hpet_read(HPET_TN_CNF(i)) & ~HPET_TN_CNF_INT_ENB);
    }

    hpet_write(HPET_CNT, 0);
    hpet_write(HPET_CNF, hpet_read(HPET_CNF) | HPET_CNF_ENABLE);
}

uint64_t read_hpet(void) {
    return hpet_read(HPET_CNT);
}
