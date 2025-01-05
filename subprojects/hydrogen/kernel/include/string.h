#ifndef HYDROGEN_STRING_H
#define HYDROGEN_STRING_H

#include <stddef.h>

int memcmp(const void *lhs, const void *rhs, size_t count);

void *memcpy(void *dest, const void *src, size_t count);

void *memmove(void *dest, const void *src, size_t count);

void *memset(void *dest, int ch, size_t count);

size_t strlen(const char *s);

size_t strnlen(const char *s, size_t max);

#define strcmp __builtin_strcmp

#endif // HYDROGEN_STRING_H
