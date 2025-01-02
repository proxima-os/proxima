.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.type idt_stub_common, @function
idt_stub_common:
    testl $3, 24(%rsp)
    jz 1f
    swapgs
1:
    sub $120, %rsp
    mov %rax, (%rsp)
    mov %rbx, 8(%rsp)
    mov %rcx, 16(%rsp)
    mov %rdx, 24(%rsp)
    mov %rsi, 32(%rsp)
    mov %rdi, 40(%rsp)
    mov %rbp, 48(%rsp)
    mov %r8, 56(%rsp)
    mov %r9, 64(%rsp)
    mov %r10, 72(%rsp)
    mov %r11, 80(%rsp)
    mov %r12, 88(%rsp)
    mov %r13, 96(%rsp)
    mov %r14, 104(%rsp)
    mov %r15, 112(%rsp)

    .cfi_startproc
    .cfi_signal_frame
    .cfi_def_cfa rsp, 176
    .cfi_rel_offset rax, 0
    .cfi_rel_offset rbx, 8
    .cfi_rel_offset rcx, 16
    .cfi_rel_offset rdx, 24
    .cfi_rel_offset rsi, 32
    .cfi_rel_offset rdi, 40
    .cfi_rel_offset rbp, 48
    .cfi_rel_offset r8, 56
    .cfi_rel_offset r9, 64
    .cfi_rel_offset r10, 72
    .cfi_rel_offset r11, 80
    .cfi_rel_offset r12, 88
    .cfi_rel_offset r13, 96
    .cfi_rel_offset r14, 104
    .cfi_rel_offset r15, 112
    .cfi_rel_offset rip, 136
    .cfi_rel_offset cs, 144
    .cfi_rel_offset rflags, 152
    .cfi_rel_offset rsp, 160
    .cfi_rel_offset ss, 168

    mov %rsp, %rdi
    cld
#ifndef NDEBUG
    xor %ebp, %ebp
#endif
    call idt_dispatch

    .cfi_endproc

    mov (%rsp), %rax
    mov 8(%rsp), %rbx
    mov 16(%rsp), %rcx
    mov 24(%rsp), %rdx
    mov 32(%rsp), %rsi
    mov 40(%rsp), %rdi
    mov 48(%rsp), %rbp
    mov 56(%rsp), %r8
    mov 64(%rsp), %r9
    mov 72(%rsp), %r10
    mov 80(%rsp), %r11
    mov 88(%rsp), %r12
    mov 96(%rsp), %r13
    mov 104(%rsp), %r14
    mov 112(%rsp), %r15
    add $136, %rsp
    testl $3, 8(%rsp)
    jz 1f
    swapgs
1:  iretq
.size idt_stub_common, . - idt_stub_common

.pushsection ".rodata.idt_stubs", "a", @progbits
.balign 8
.globl idt_stubs
.type idt_stubs, @object
idt_stubs:
.popsection

.balign 16
.type idt_stub_code, @function
idt_stub_code:

.macro idt_stub vec, errc=0

1:
.if \errc == 0
    pushq $0
.endif
    pushq $\vec
    jmp idt_stub_common

.pushsection ".rodata.idt_stubs", "a", @progbits
.org \vec * 8
.quad 1b
.popsection

.endm

idt_stub 0
idt_stub 1
idt_stub 2
idt_stub 3
idt_stub 4
idt_stub 5
idt_stub 6
idt_stub 7
idt_stub 8, errc=1
idt_stub 10, errc=1
idt_stub 11, errc=1
idt_stub 12, errc=1
idt_stub 13, errc=1
idt_stub 14, errc=1
idt_stub 16
idt_stub 17
idt_stub 18
idt_stub 19
idt_stub 20
idt_stub 21

.set .Li, 32
.rept 256 - .Li
idt_stub .Li
.set .Li, .Li + 1
.endr

.size idt_stub_code, . - idt_stub_code

.pushsection ".rodata.idt_stubs", "a", @progbits
.size idt_stubs, . - idt_stubs
.popsection
