#include "cpu/cpu.h"
#include "asm/cpuid.h"
#include "asm/cr.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "cpu/tss.h"
#include "mem/memlayout.h"
#include "sys/syscall.h"
#include <stdint.h>

#define CR0_CLEAR_MASK (CR0_EM | CR0_TS)
#define CR0_SET_MASK (CR0_MP | CR0_NE | CR0_AM)

bool pg_supported;
bool nx_supported;
bool gb_pages_supported;
bool tsc_supported;
bool tsc_deadline_supported;
bool running_in_hypervisor;
bool tsc_invariant;
bool xsave_supported;
bool fsgsbase_supported;
bool smap_supported;
uint64_t cpu_paddr_mask;
static bool de_supported;
static bool smep_supported;
static bool umip_supported;

__attribute__((aligned(16))) static unsigned char fatal_stack[KERNEL_STACK_SIZE];

cpu_init_data_t bsp_init_data = {.tss.fatal_stack = (uintptr_t)fatal_stack + sizeof(fatal_stack)};
size_t num_cpus = 1;

void detect_cpu(void) {
    unsigned eax, ebx, ecx, edx;

    if (try_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        tsc_deadline_supported = ecx & (1u << 24);
        xsave_supported = ecx & (1u << 26);
        running_in_hypervisor = ecx & (1u << 31);

        de_supported = edx & (1u << 2);
        tsc_supported = edx & (1u << 4);
        pg_supported = edx & (1u << 13);
    }

    if (try_cpuid2(7, 0, &eax, &ebx, &ecx, &edx)) {
        fsgsbase_supported = ebx & (1u << 0);
        smep_supported = ebx & (1u << 7);
        smap_supported = ebx & (1u << 20);

        umip_supported = ecx & (1u << 2);
    }

    if (try_cpuid(0x80000001, &eax, &ebx, &ecx, &edx)) {
        nx_supported = edx & (1u << 20);
        gb_pages_supported = edx & (1u << 26);
    }

    if (try_cpuid(0x80000007, &eax, &ebx, &ecx, &edx)) {
        tsc_invariant = edx & (1u << 8);
    }

    if (try_cpuid(0x80000008, &eax, &ebx, &ecx, &edx)) {
        int shift = eax & 0xff;

        if (shift < 64) cpu_paddr_mask = (1ul << shift) - 1;
        else cpu_paddr_mask = UINT64_MAX;
    } else {
        cpu_paddr_mask = (1ul << 36) - 1;
    }
}

void init_cpu(cpu_init_data_t *data) {
    data->cpu.self = &data->cpu;

    write_cr0((read_cr0() & ~CR0_CLEAR_MASK) | CR0_SET_MASK);

    size_t cr4 = read_cr4() | CR4_OSXMMEXCPT | CR4_OSFXSR;

    if (de_supported) cr4 |= CR4_DE;
    if (tsc_supported) cr4 &= ~CR4_TSD;
    if (fsgsbase_supported) cr4 |= CR4_FSGSBASE;
    if (smep_supported) cr4 |= CR4_SMEP;
    if (smap_supported) cr4 |= CR4_SMAP;
    if (umip_supported) cr4 |= CR4_UMIP;

    write_cr4(cr4);

    init_gdt(&data->cpu);
    init_tss(&data->tss);
    load_idt();
    syscall_init();
}
