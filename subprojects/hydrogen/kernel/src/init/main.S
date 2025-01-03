#include "mem/memlayout.h"

.text

.balign 16
.globl _entry
.type _entry, @function
_entry:
    lea .Lstack_top(%rip), %rsp
    call kernel_main
    ud2
.size _entry, . - _entry

.bss

.balign 16
.type idle_stack, @object
idle_stack: .space KERNEL_STACK_SIZE
.Lstack_top:
.size idle_stack, . - idle_stack
