#include "cpu/tss.h"
#include "mem/memlayout.h"
#include <stdint.h>

__attribute__((aligned(16))) static unsigned char fatal_stack[KERNEL_STACK_SIZE];

tss_t kernel_tss = {
        .ist =
                {
                        [0] = (uintptr_t)fatal_stack + sizeof(fatal_stack),
                },
        .io_map_base = sizeof(kernel_tss),
};
