#ifndef LD_STRING_H
#define LD_STRING_H

#include <stddef.h>

int memcmp(const void *s1, const void *s2, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *dest, int value, size_t n);

int strcmp(const char *s1, const char *s2);

#endif // LD_STRING_H
