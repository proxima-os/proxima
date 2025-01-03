#ifndef HYDROGEN_CPU_TSS_H
#define HYDROGEN_CPU_TSS_H

#include <stdint.h>

typedef struct {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t io_map_base;
} __attribute__((aligned(8), packed)) cpu_tss_t;

typedef struct {
    uintptr_t fatal_stack;
} tss_init_data_t;

void init_tss(tss_init_data_t *data);

#endif // HYDROGEN_CPU_TSS_H
