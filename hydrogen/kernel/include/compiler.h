#ifndef HYDROGEN_COMPILER_H
#define HYDROGEN_COMPILER_H

#define UNUSED __attribute__((unused))

#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))

#endif // HYDROGEN_COMPILER_H
