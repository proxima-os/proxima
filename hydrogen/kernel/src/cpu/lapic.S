.text

.balign 16
.globl park_ap
.type park_ap, @function
park_ap:
    mov %rdi, %r12
    call switch_to_kernel_mappings # make sure this cpu isn't using page tables that will be reclaimed later
    xor %eax, %eax
    mov %rax, 24(%r12)
1:  hlt
    jmp 1b
.size park_ap, . - park_ap
