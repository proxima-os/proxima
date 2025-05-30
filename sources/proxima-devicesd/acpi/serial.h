#pragma once

#include <uacpi/namespace.h>

uacpi_iteration_decision handle_serial(void *ctx, uacpi_namespace_node *node, uacpi_u32 depth);

void serial_handle_readable(void);
void serial_handle_writable(void);

void serial_init_late(void);
