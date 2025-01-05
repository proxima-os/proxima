#include "hydrogen/sched.h"
#include "hydrogen/vfs.h"
#include "link.h"
#include "proxima/compiler.h"
#include "proxima/elf.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

static void prints(const char *s) {
    if (!s) s = "(null)";

    size_t len = 0;
    while (s[len] != 0) len++;
    hydrogen_write(1, s, len);
}

static void printc(char c) {
    hydrogen_write(1, &c, sizeof(c));
}

static void printu(uint64_t value, unsigned base) {
    unsigned char buf[32];
    size_t index = sizeof(buf);

    do {
        buf[--index] = "0123456789abcdef"[value % base];
        value /= base;
    } while (index > 0 && value > 0);

    size_t size = sizeof(buf) - index;
    hydrogen_write(1, &buf[index], size);
}

static void printd(int64_t value) {
    if (value < 0) {
        printc('-');
        value = -value;
    }
    printu(value, 10);
}

static void printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    size_t last = 0;
    size_t i;

    for (i = 0; format[i] != 0; i++) {
        if (format[i] == '%') {
            if (last != i) hydrogen_write(1, &format[last], i - last);

            switch (format[++i]) {
            case 0: i--; break;
            case 'c': printc(va_arg(args, int)); break;
            case 's': prints(va_arg(args, const char *)); break;
            case 'p':
                prints("0x");
                printu((uintptr_t)va_arg(args, void *), 16);
                break;
            case 'd': printd(va_arg(args, int32_t)); break;
            case 'u': printu(va_arg(args, uint32_t), 10); break;
            case 'x': printu(va_arg(args, uint32_t), 16); break;
            case 'D': printd(va_arg(args, int64_t)); break;
            case 'U': printu(va_arg(args, uint64_t), 10); break;
            case 'X': printu(va_arg(args, uint64_t), 16); break;
            }

            last = i + 1;
        }
    }

    if (last != i) hydrogen_write(1, &format[last], i - last);

    va_end(args);
}

__attribute__((used)) HIDDEN _Noreturn void ld_main(
        size_t argc,
        char *argv[],
        char *envp[],
        elf_auxv_t *auxv,
        uintptr_t base
) {
    for (elf_auxv_t *cur = auxv; cur->a_type != AT_NULL; cur++) {
        if (cur->a_type == AT_SYSINFO_EHDR) {
            vdso_image = cur->a_ptr;
            break;
        }
    }

    setup_vdso();
    link_self(base);

    printf("Hello from userspace! This is being printed from the dynamic linker.\n");

    printf("argc = %U\n", argc);

    for (size_t i = 0; i <= argc; i++) {
        printf(" argv[%U] = %p (`%s`)\n", i, argv[i], argv[i]);
    }

    printf("envp:\n");

    size_t i = 0;
    for (;;) {
        char *env = envp[i];
        printf(" envp[%U] = %p (`%s`)\n", i, env, env);
        if (!env) break;
        i++;
    }

    prints("auxv:\n");

    i = 0;
    for (;;) {
        elf_auxv_t *value = &auxv[i];
        printf(" auxv[%U] = %p: {%d, 0x%X}\n", i, value, value->a_type, value->a_val);
        if (value->a_type == AT_NULL) break;
        i++;
    }

    hydrogen_exit();
}
