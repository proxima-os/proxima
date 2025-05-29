#include "acpi.h"
#include "acpi/kernel-api.h"
#include "compiler.h"
#include "main.h"
#include "pci/pci.h"
#include <errno.h>
#include <fcntl.h>
#include <hydrogen/thread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uacpi/event.h>
#include <uacpi/sleep.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

int gsi_fd;
int isa_irq_fd = -1;

static void do_shutdown(void *ctx) {
    (void)ctx;

    uacpi_status ret = uacpi_prepare_for_sleep_state(UACPI_SLEEP_STATE_S5);
    if (uacpi_unlikely_error(ret)) {
        fprintf(stderr, "devicesd: failed to prepare for shutdown: %s\n", acpi_error_string(ret));
        return;
    }

    disable_interrupts = true;

    ret = uacpi_enter_sleep_state(UACPI_SLEEP_STATE_S5);
    if (uacpi_unlikely_error(ret)) {
        fprintf(stderr, "devicesd: shutdown failed: %s\n", acpi_error_string(ret));
        disable_interrupts = false;
        return;
    }

    for (;;) {
        hydrogen_thread_sleep(0);
    }
}

static uacpi_interrupt_ret handle_power_button(uacpi_handle ctx) {
    if (!queue_task(do_shutdown, ctx)) {
        fprintf(stderr, "devicesd: failed to allocate shutdown task\n");
    }

    return UACPI_INTERRUPT_HANDLED;
}

void acpi_init(void) {
    FILE *file = fopen("/dev/acpi/rsdp", "r");
    if (!file) {
        if (errno == ENOENT) {
            fprintf(stderr, "devicesd: could not find rsdp address, not initializing acpi\n");
            return;
        }

        perror("devicesd: failed to find rsdp address");
        return;
    }

    if (fscanf(file, "%" SCNx64, &rsdp_phys) < 1) {
        perror("devicesd: failed to find rsdp address");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    gsi_fd = open("/dev/acpi/gsi", O_RDWR);
    if (gsi_fd < 0) {
        perror("devicesd: failed to open /dev/acpi/gsi");
        exit(EXIT_FAILURE);
    }

    isa_irq_fd = open("/dev/isa-irq", O_RDWR);
    if (isa_irq_fd < 0 && errno != ENOENT) {
        perror("devicesd: failed to open /dev/isa-irq");
        exit(EXIT_FAILURE);
    }

    uint64_t bitmask = 1;
    int error = hydrogen_thread_set_cpu_affinity(&bitmask, 1);
    if (unlikely(error)) {
        fprintf(stderr, "devicesd: failed to pin daemon to cpu 0: %s\n", strerror(error));
        exit(EXIT_FAILURE);
    }

    uacpi_status status = uacpi_initialize(0);
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to initialize uacpi: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    pci_init_acpi_tables();

    status = uacpi_namespace_load();
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to load acpi namespace: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    status = uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC);
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to set acpi interrupt model: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    status = uacpi_namespace_initialize();
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to initialize acpi namespace: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    status = uacpi_finalize_gpe_initialization();
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to initialize acpi gpes: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }

    status = uacpi_install_fixed_event_handler(UACPI_FIXED_EVENT_POWER_BUTTON, handle_power_button, NULL);
    if (uacpi_unlikely_error(status)) {
        fprintf(stderr, "devicesd: failed to install power button handler: %s\n", acpi_error_string(status));
        exit(EXIT_FAILURE);
    }
}
