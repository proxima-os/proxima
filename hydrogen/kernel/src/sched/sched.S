.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl switch_task
.type switch_task, @function
switch_task:
    mov %rbx, (%rdi)
    mov %rbp, 8(%rdi)
    mov %rsp, 16(%rdi)
    mov %r12, 24(%rdi)
    mov %r13, 32(%rdi)
    mov %r14, 40(%rdi)
    mov %r15, 48(%rdi)

    mov (%rsi), %rbx
    mov 8(%rsi), %rbp
    mov 16(%rsi), %rsp
    mov 24(%rsi), %r12
    mov 32(%rsi), %r13
    mov 40(%rsi), %r14
    mov 48(%rsi), %r15

    ret
.size switch_task, . - switch_task

.balign 16
.globl task_init_stub
.type task_init_stub, @function
task_init_stub:
.cfi_startproc
.cfi_undefined rip
    mov %rbx, %rdi
    mov %r12, %rsi
    mov %r13, %rdx
    call sched_init_task
    ud2
.cfi_endproc
.size task_init_stub, . - task_init_stub
