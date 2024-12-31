#include "util/panic.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "cpu/cpu.h"
#include "cpu/irqvec.h"
#include "cpu/lapic.h"
#include "util/print.h"
#include <stdarg.h>
#include <stdint.h>

_Noreturn void panic(const char *format, ...) {
    disable_irq();
    lapic_send_ipi(NULL, IPI_PANIC);

    printk("panic on cpu %U: ", current_cpu.id);
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
    printk("\n");

    for (;;) cpu_idle();
}
