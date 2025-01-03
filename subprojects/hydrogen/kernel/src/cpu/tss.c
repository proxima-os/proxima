#include "cpu/tss.h"
#include "cpu/cpu.h"
#include <stdint.h>

void init_tss(tss_init_data_t *data) {
        current_cpu.tss.ist[0] = data->fatal_stack;
        current_cpu.tss.io_map_base = sizeof(current_cpu.tss);
}
