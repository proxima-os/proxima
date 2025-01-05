#ifndef HYDROGEN_UTIL_PRINT_H
#define HYDROGEN_UTIL_PRINT_H

#include "fs/vfs.h"
#include <stdarg.h>
#include <stddef.h>

void init_print(void);

int create_kcon_handle(file_t **out);

void map_print(void);

void vprintk(const char *format, va_list args);

void printk(const char *format, ...);

size_t vsnprintk(void *buf, size_t size, const char *format, va_list args);

size_t snprintk(void *buf, size_t size, const char *format, ...);

#endif // HYDROGEN_UTIL_PRINT_H
