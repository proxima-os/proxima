#include "util/panic.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "util/print.h"
#include <stdarg.h>
#include <stdint.h>

_Noreturn void panic(const char *format, ...) {
    disable_irq();

    printk("panic: ");
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
    printk("\n");

    for (;;) cpu_idle();
}
