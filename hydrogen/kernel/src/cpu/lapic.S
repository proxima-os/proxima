.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl start_ap
.type start_ap, @function
start_ap:
    .cfi_startproc
    .cfi_undefined rip
    mov %rdi, %r12
    and $~15, %rsp
    call switch_to_kernel_mappings # this might be necessary to access the idle stack
    mov 24(%r12), %rdi
    mov (%rdi), %rsp
    call do_start_ap
    ud2
    .cfi_endproc
.size start_ap, . - start_ap
