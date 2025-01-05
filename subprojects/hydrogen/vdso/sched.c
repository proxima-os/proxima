#include "hydrogen/sched.h"
#include "sys/sysvecs.h"
#include "syscall.h"

_Noreturn void hydrogen_exit(void) {
    syscall0(SYS_EXIT);
    __builtin_trap();
}
