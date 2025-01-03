#include "compiler.h"
#include <stddef.h>
#include <stdint.h>

HIDDEN int memcmp(const void *lhs, const void *rhs, size_t count) {
    const unsigned char *byte_lhs = lhs;
    const unsigned char *byte_rhs = rhs;
    size_t i;

    for (i = 0; i < count; ++i) {
        if (byte_lhs[i] != byte_rhs[i]) return byte_lhs[i] - byte_rhs[i];
    }

    return 0;
}

HIDDEN void *memcpy(void *dest, const void *src, size_t count) {
    unsigned char *cd = dest;
    const unsigned char *cs = src;

    while (count--) *cd++ = *cs++;

    return dest;
}

HIDDEN void *memmove(void *dest, const void *src, size_t count) {
    unsigned char *cd = dest;
    const unsigned char *cs = src;

    if (src < dest) {
        cs += count;
        cd += count;

        while (count--) *--cd = *--cs;
    } else {
        while (count--) *cd++ = *cs++;
    }

    return dest;
}

HIDDEN void *memset(void *dest, int ch, size_t count) {
    unsigned char fill = ch;
    unsigned char *cdest = dest;

    while (count--) *cdest++ = fill;

    return dest;
}

HIDDEN int strcmp(const char *s1, const char *s2) {
    size_t i = 0;

    for (;;) {
        unsigned char c1 = s1[i];
        unsigned char c2 = s2[i];

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0) return 0;

        i += 1;
    }
}
