.section ".text.memcmp", "ax", @progbits

.balign 16
.globl memcmp
.type memcmp, @function
memcmp:
    xor %eax, %eax
    cmp %rdi, %rsi
    je .Lmemcmp_done
    test %rdx, %rdx
    jz .Lmemcmp_done
.balign 16
.Lmemcmp_test:
    mov (%rdi), %al
    sub (%rsi), %al
    jne .Lmemcmp_done
    inc %rdi
    inc %rsi
    dec %rdx
    jnz .Lmemcmp_test
.Lmemcmp_done:
    movsx %al, %eax
    ret
.size memcmp, . - memcmp

.section ".text.memcpy", "ax", @progbits

.balign 16
.globl memcpy
.type memcpy, @function
memcpy:
    mov %rdi, %rax
    mov %rdx, %rcx
    rep movsb
    ret
.size memcpy, . - memcpy

.section ".text.memmove", "ax", @progbits

.balign 16
.globl memmove
.type memmove, @function
memmove:
    mov %rdi, %rax
    mov %rdx, %rcx

    cmp %rsi, %rdi
    je .Lmemmove_done # if dest = src, we're done
    jb .Lmemmove_start # if dest < src, copy forwards
    add %rcx, %rdi # dest > src, copy backwards
    add %rcx, %rsi
    std
.Lmemmove_start:
    rep movsb
    cld
.Lmemmove_done:
    ret
.size memmove, . - memmove

.section ".text.memset", "ax", @progbits

.balign 16
.globl memset
.type memset, @function
memset:
    mov %rdi, %r8
    mov %rsi, %rax
    mov %rdx, %rcx
    rep stosb
    mov %r8, %rax
    ret
.size memset, . - memset
