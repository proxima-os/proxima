#include "cpu/exc.h"
#include "asm/cr.h"
#include "asm/idle.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "proxima/compiler.h"
#include "util/panic.h"
#include <stdbool.h>

void handle_fatal_exception(idt_frame_t *frame) {
    if (frame->vector == 2 || frame->vector == 8 || frame->vector == 18) paranoid_enter(frame);

    panic("unhandled exception %U (error code 0x%X) at 0x%X\n"
          "rax=0x%16X rbx=0x%16X rcx=0x%16X rdx=0x%16X\n"
          "rsi=0x%16X rdi=0x%16X rbp=0x%16X rsp=0x%16X\n"
          "r8 =0x%16X r9 =0x%16X r10=0x%16X r11=0x%16X\n"
          "r12=0x%16X r13=0x%16X r14=0x%16X r15=0x%16X\n"
          "rfl=0x%X cr0=0x%X cr2=0x%X cr3=0x%X cr4=0x%X cr8=0x%X",
          frame->vector,
          frame->error_code,
          frame->rip,
          frame->rax,
          frame->rbx,
          frame->rcx,
          frame->rdx,
          frame->rsi,
          frame->rdi,
          frame->rbp,
          frame->rsp,
          frame->r8,
          frame->r9,
          frame->r10,
          frame->r11,
          frame->r12,
          frame->r13,
          frame->r14,
          frame->r15,
          frame->rflags,
          read_cr0(),
          read_cr2(),
          read_cr3(),
          read_cr4(),
          read_cr8());
}

static void handle_ipi_panic(UNUSED idt_frame_t *frame) {
    for (;;) cpu_idle();
}

void init_exc(void) {
    idt_install(0, handle_fatal_exception);
    idt_install(1, handle_fatal_exception);
    idt_install(2, handle_fatal_exception);
    idt_install(3, handle_fatal_exception);
    idt_install(4, handle_fatal_exception);
    idt_install(5, handle_fatal_exception);
    idt_install(6, handle_fatal_exception);
    idt_install(7, handle_fatal_exception);
    idt_install(8, handle_fatal_exception);
    idt_install(10, handle_fatal_exception);
    idt_install(11, handle_fatal_exception);
    idt_install(12, handle_fatal_exception);
    idt_install(13, handle_fatal_exception);
    idt_install(16, handle_fatal_exception);
    idt_install(17, handle_fatal_exception);
    idt_install(18, handle_fatal_exception);
    idt_install(19, handle_fatal_exception);
    idt_install(20, handle_fatal_exception);
    idt_install(21, handle_fatal_exception);
    idt_install(IPI_PANIC, handle_ipi_panic);
}
