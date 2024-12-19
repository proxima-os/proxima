#ifndef HYDROGEN_UTIL_PANIC_H
#define HYDROGEN_UTIL_PANIC_H

#include <stdint.h>

_Noreturn void panic(const char *format, ...);

#if !defined(NDEBUG) || PROXIMA_ASSERTIONS
#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
        if (!(x)) panic("assertion `%s` failed in %s at %s:%d", #x, __func__, __FILE__, __LINE__);                     \
    } while (0)
#else
#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
    } while (0)
#endif

#endif // HYDROGEN_UTIL_PANIC_H
