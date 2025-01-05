#ifndef VDSO_SYSCALL_H
#define VDSO_SYSCALL_H

#include "sys/sysvecs.h"
#include <stddef.h>

static inline syscall_result_t syscall0(syscall_vector_t vector) {
    syscall_result_t result;
    asm volatile("syscall" : "=a"(result.value), "=d"(result.error) : "a"(vector) : "memory");
    return result;
}

static inline syscall_result_t syscall1(syscall_vector_t vector, size_t a0) {
    syscall_result_t result;
    asm volatile("syscall" : "=a"(result.value), "=d"(result.error) : "a"(vector), "D"(a0) : "memory");
    return result;
}

static inline syscall_result_t syscall2(syscall_vector_t vector, size_t a0, size_t a1) {
    syscall_result_t result;
    asm volatile("syscall" : "=a"(result.value), "=d"(result.error) : "a"(vector), "D"(a0), "S"(a1) : "memory");
    return result;
}

static inline syscall_result_t syscall3(syscall_vector_t vector, size_t a0, size_t a1, size_t a2) {
    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value), "=d"(result.error)
                 : "a"(vector), "D"(a0), "S"(a1), "d"(a2)
                 : "memory");
    return result;
}

static inline syscall_result_t syscall4(syscall_vector_t vector, size_t a0, size_t a1, size_t a2, size_t a3) {
    register size_t r10 asm("r10") = a3;

    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value), "=d"(result.error)
                 : "a"(vector), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                 : "memory");
    return result;
}

static inline syscall_result_t syscall5(
        syscall_vector_t vector,
        size_t a0,
        size_t a1,
        size_t a2,
        size_t a3,
        size_t a4
) {
    register size_t r10 asm("r10") = a3;
    register size_t r8 asm("r8") = a4;

    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value), "=d"(result.error)
                 : "a"(vector), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
                 : "memory");
    return result;
}

static inline syscall_result_t syscall6(
        syscall_vector_t vector,
        size_t a0,
        size_t a1,
        size_t a2,
        size_t a3,
        size_t a4,
        size_t a5
) {
    register size_t r10 asm("r10") = a3;
    register size_t r8 asm("r8") = a4;
    register size_t r9 asm("r9") = a5;

    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value), "=d"(result.error)
                 : "a"(vector), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                 : "memory");
    return result;
}

#endif // VDSO_SYSCALL_H
