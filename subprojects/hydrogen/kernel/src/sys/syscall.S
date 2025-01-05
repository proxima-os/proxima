.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl syscall_entry
.type syscall_entry, @function
syscall_entry:
    swapgs
    mov %rsp, %gs:8
    mov %gs:16, %rsp

    # Create idt_frame_t on stack
    sub $0xb0, %rsp
    mov %rax, 0x00(%rsp)
    mov %rbx, 0x08(%rsp)
    mov %rcx, 0x10(%rsp)
    mov %rdx, 0x18(%rsp)
    mov %rsi, 0x20(%rsp)
    mov %rdi, 0x28(%rsp)
    mov %rbp, 0x30(%rsp)
    mov %r8, 0x38(%rsp)
    mov %r9, 0x40(%rsp)
    mov %r10, 0x48(%rsp)
    mov %r11, 0x50(%rsp)
    mov %r12, 0x58(%rsp)
    mov %r13, 0x60(%rsp)
    mov %r14, 0x68(%rsp)
    mov %r15, 0x70(%rsp)
    mov %rcx, 0x88(%rsp)
    mov %r11, 0x98(%rsp)
    mov %gs:8, %rdi
    mov %rdi, 0xa0(%rsp)

#ifndef NDEBUG
    xor %ebp, %ebp
#endif
    mov %rsp, %rdi
    call syscall_dispatch

    # Load registers
    mov 0x00(%rsp), %rax
    mov 0x08(%rsp), %rbx
    mov 0x10(%rsp), %rcx
    mov 0x18(%rsp), %rdx
    mov 0x20(%rsp), %rsi
    mov 0x28(%rsp), %rdi
    mov 0x30(%rsp), %rbp
    mov 0x38(%rsp), %r8
    mov 0x40(%rsp), %r9
    mov 0x48(%rsp), %r10
    mov 0x50(%rsp), %r11
    mov 0x58(%rsp), %r12
    mov 0x60(%rsp), %r13
    mov 0x68(%rsp), %r14
    mov 0x70(%rsp), %r15
    mov 0x88(%rsp), %rcx
    mov 0x98(%rsp), %r11
    mov 0xa0(%rsp), %rsp
    swapgs
    sysretq
.size syscall_entry, . - syscall_entry

.balign 16
.globl normal_memcpy_user
.type normal_memcpy_user, @function
normal_memcpy_user:
    mov %rdx, %rcx
    rep movsb
    xor %eax, %eax
    ret
.size normal_memcpy_user, . - normal_memcpy_user

.balign 16
.globl normal_memset_user
.type normal_memset_user, @function
normal_memset_user:
    mov %rsi, %rax
    mov %rdx, %rcx
    rep stosb
    xor %eax, %eax
    ret
.size normal_memset_user, . - normal_memset_user

.balign 16
.globl smap_memcpy_user
.type smap_memcpy_user, @function
smap_memcpy_user:
    mov %rdx, %rcx
    stac
    rep movsb
    clac
    xor %eax, %eax
    ret
.size smap_memcpy_user, . - smap_memcpy_user

.balign 16
.globl smap_memset_user
.type smap_memset_user, @function
smap_memset_user:
    mov %rsi, %rax
    mov %rdx, %rcx
    stac
    rep stosb
    clac
    xor %eax, %eax
    ret
.size smap_memset_user, . - smap_memset_user
