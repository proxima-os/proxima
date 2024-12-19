.text

.balign 16
.globl switch_segments
.type switch_segments, @function
switch_segments:
    push %rdi
    lea 1f(%rip), %rax
    push %rax
    lretq
1:  xor %eax, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %esi, %ss
    ret
.size switch_segments, . - switch_segments
