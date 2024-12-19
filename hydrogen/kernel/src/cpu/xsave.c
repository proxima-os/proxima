#include "cpu/xsave.h"
#include "asm/cpuid.h"
#include "asm/cr.h"
#include "cpu/cpu.h"
#include "mem/heap.h"
#include "sched/sched.h"
#include "string.h"
#include "util/panic.h"
#include "util/print.h"
#include <stddef.h>

typedef enum {
    CTX_FXSAVE,
    CTX_XSAVE,
    CTX_XSAVEOPT,
} ctx_style_t;

static ctx_style_t ctx_style;
static size_t ctx_size;

static void detect_xsave(void) {
    if (!xsave_supported) {
        ctx_style = CTX_FXSAVE;
        ctx_size = 512;
        return;
    }

    write_cr4(read_cr4() | CR4_OSXSAVE);
    ctx_style = CTX_XSAVE;

    // Set xcr0
    unsigned eax, ebx, ecx, edx;
    cpuid2(0x0d, 0, &eax, &ebx, &ecx, &edx);
    write_xcr(0, ((uint64_t)edx << 32) | eax);

    // Get context area size
    cpuid2(0x0d, 0, &eax, &ebx, &ecx, &edx);
    ctx_size = ebx;

    // Detect xsave features
    cpuid2(0x0d, 1, &eax, &ebx, &ecx, &edx);
    if (eax & (1u << 0)) ctx_style = CTX_XSAVEOPT;
}

void init_xsave(void) {
    detect_xsave();
    printk("xsave: context is %U bytes (style %d)\n", ctx_size, ctx_style);

    current_task->xsave_area = kalloc(ctx_size);
    if (!current_task->xsave_area) panic("failed to allocate xsave area for idle task");
    memset(current_task->xsave_area, 0, ctx_size);
    xreset();
}

static void do_xsave(void *ptr) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxsaveq (%0)" ::"r"(ptr)); break;
    case CTX_XSAVE: asm("xsave (%0)" ::"r"(ptr), "d"(-1), "a"(-1)); break;
    case CTX_XSAVEOPT: asm("xsaveopt (%0)" ::"r"(ptr), "d"(-1), "a"(-1)); break;
    }
}

void *alloc_xsave(void) {
    void *ptr = kalloc(ctx_size);
    if (ptr) do_xsave(ptr);
    return ptr;
}

void free_xsave(void *ptr) {
    kfree(ptr);
}

void xsave(void) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxsaveq (%0)" ::"r"(current_task->xsave_area)); break;
    case CTX_XSAVE: asm("xsave (%0)" ::"r"(current_task->xsave_area), "d"(-1), "a"(-1)); break;
    case CTX_XSAVEOPT: asm("xsaveopt (%0)" ::"r"(current_task->xsave_area), "d"(-1), "a"(-1)); break;
    }
}

void xrestore(void) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxrstorq (%0)" ::"r"(current_task->xsave_area)); break;
    case CTX_XSAVE:
    case CTX_XSAVEOPT: asm("xrstor (%0)" ::"r"(current_task->xsave_area), "d"(-1), "a"(-1)); break;
    }
}

void xreset(void) {
    memset(current_task->xsave_area, 0, ctx_size);
    xrestore();
    uint32_t mxcsr = 0x1f80;
    asm("ldmxcsr %0" ::"m"(mxcsr));
}
