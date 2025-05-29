#pragma once

#include <string.h>
#include <uacpi/types.h>

extern int gsi_fd;
extern int isa_irq_fd;

void acpi_init(void);

static inline uacpi_status os_to_acpi_error(int error) {
    return -error;
}

static inline const char *acpi_error_string(uacpi_status status) {
    if ((int)status >= 0) return uacpi_status_to_string(status);
    return strerror(-status);
}
