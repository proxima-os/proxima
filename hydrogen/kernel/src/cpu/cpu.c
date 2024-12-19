#include "cpu/cpu.h"
#include "asm/cpuid.h"
#include "asm/cr.h"
#include "cpu/exc.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"

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

void init_cpu(void) {
    write_cr0((read_cr0() & ~CR0_CLEAR_MASK) | CR0_SET_MASK);

    size_t cr4 = read_cr4() | CR4_OSXMMEXCPT | CR4_OSFXSR;
    unsigned eax, ebx, ecx, edx;

    if (try_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        tsc_deadline_supported = ecx & (1u << 24);
        xsave_supported = ecx & (1u << 26);
        running_in_hypervisor = ecx & (1u << 31);

        if (edx & (1u << 2)) cr4 |= CR4_DE;

        if (edx & (1u << 4)) {
            cr4 &= ~CR4_TSD;
            tsc_supported = true;
        }

        pg_supported = edx & (1u << 13);
    }

    if (try_cpuid2(7, 0, &eax, &ebx, &ecx, &edx)) {
        if (ebx & (1u << 0)) {
            cr4 |= CR4_FSGSBASE;
            fsgsbase_supported = true;
        }

        if (ebx & (1u << 7)) cr4 |= CR4_SMEP;

        if (ebx & (1u << 20)) {
            cr4 |= CR4_SMAP;
            smap_supported = true;
        }

        if (ecx & (1u << 2)) cr4 |= CR4_UMIP;
    }

    if (try_cpuid(0x80000001, &eax, &ebx, &ecx, &edx)) {
        nx_supported = edx & (1u << 20);
        gb_pages_supported = edx & (1u << 26);
    }

    if (try_cpuid(0x80000007, &eax, &ebx, &ecx, &edx)) {
        tsc_invariant = edx & (1u << 8);
    }

    write_cr4(cr4);

    init_gdt();
    init_idt();
    init_exc();
}
