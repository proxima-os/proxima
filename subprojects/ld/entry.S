.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl _start
.hidden _start
.type _start, @function
_start:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp
    xor %ebp, %ebp
    mov (%rsp), %rdi # load argc into a0
    lea 8(%rsp), %rsi # load argv into a1
    lea 16(%rsp,%rdi,8), %rdx # load envp into a2
    # find auxv start and put it into a3
    mov %rdx, %rcx
1:  add $8, %rcx
    cmpq $0, -8(%rcx)
    jne 1b

    # load image base into a4
    lea __executable_start(%rip), %r8
    call ld_main
    ud2
    .cfi_endproc
.size _start, . - _start
