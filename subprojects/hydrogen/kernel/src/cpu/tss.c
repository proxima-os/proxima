#include "cpu/tss.h"
#include "cpu/cpu.h"
#include <stdint.h>

void init_tss(tss_init_data_t *data) {
    current_cpu.tss.ist[0] = data->fatal_stack;
    current_cpu.tss.io_map_base = sizeof(current_cpu.tss);

    // Store the correct GS base value above the IRQ stack frame to facilitate paranoid entries
    for (int i = 0; i < 7; i++) {
        uintptr_t stack = current_cpu.tss.ist[i];

        if (stack) {
            stack -= 16;
            current_cpu.tss.ist[i] = stack;
            *(void **)stack = current_cpu_ptr;
        }
    }
}
