#include "compiler.h"
#include "sys/sysvecs.h"
#include "sys/vdso.h"
#include "util/time.h"
#include <stdint.h>

static _Noreturn void sys_exit(void) {
    asm("syscall" ::"a"(SYS_EXIT) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

/*static syscall_result_t sys_mmap(void *addr, size_t size, int flags) {
    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value.num), "=d"(result.error)
                 : "a"(SYS_MMAP), "D"(addr), "S"(size), "d"(flags)
                 : "rcx", "r11", "memory");
    return result;
}

static syscall_result_t sys_mprotect(void *addr, size_t size, int flags) {
    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value.num), "=d"(result.error)
                 : "a"(SYS_MPROTECT), "D"(addr), "S"(size), "d"(flags)
                 : "rcx", "r11", "memory");
    return result;
}

static syscall_result_t sys_munmap(void *addr, size_t size) {
    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value.num), "=d"(result.error)
                 : "a"(SYS_MUNMAP), "D"(addr), "S"(size)
                 : "rcx", "r11", "memory");
    return result;
}*/

static syscall_result_t sys_write(int fd, const void *buf, size_t count) {
    syscall_result_t result;
    asm volatile("syscall"
                 : "=a"(result.value.num), "=d"(result.error)
                 : "a"(SYS_WRITE), "D"(fd), "S"(buf), "d"(count)
                 : "rcx", "r11", "memory");
    return result;
}

static uint64_t get_time(void) {
    return __builtin_ia32_rdtsc() - boot_tsc;
}

static uint64_t get_ns_since_boot(void) {
    return timeconv_apply(tsc2ns_conv, get_time());
}

PROTECTED int64_t get_timestamp(void) {
    return __atomic_load_n(&boot_timestamp, __ATOMIC_ACQUIRE) + get_ns_since_boot();
}

static void printu(uint64_t value, size_t min) {
    unsigned char buffer[32];
    size_t index = sizeof(buffer);

    do {
        buffer[--index] = '0' + (value % 10);
        value /= 10;
    } while (value > 0);

    while (sizeof(buffer) - index < min) buffer[--index] = '0';

    sys_write(0, &buffer[index], sizeof(buffer) - index);
}

HIDDEN __attribute__((used)) _Noreturn void _start(void) {
    uint64_t elapsed = get_ns_since_boot();

    sys_write(0, "According to userspace, it has been ", 36);
    printu(elapsed / 1000000, 0);
    sys_write(0, ".", 1);
    printu(elapsed % 1000000, 6);
    sys_write(0, " milliseconds since boot.\n", 26);

    int64_t timestamp = get_timestamp();
    int64_t seconds = timestamp / 1000000000;
    int64_t nanoseconds = timestamp % 1000000000;
    if (nanoseconds < 0) nanoseconds = -nanoseconds;

    sys_write(0, "The current time is ", 20);
    if (timestamp < 0) sys_write(0, "-", 1);
    printu(seconds, 0);
    sys_write(0, ".", 1);
    printu(nanoseconds, 9);
    sys_write(0, " seconds since 1970-01-01T00:00:00Z.\n", 37);

    sys_exit();
}
