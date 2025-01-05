#include "sched/sched.h"
#include "sys/syscall.h"

_Noreturn void sys_exit(void) {
    sched_exit();
}
