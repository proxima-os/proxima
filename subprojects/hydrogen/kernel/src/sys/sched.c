#include "sched/sched.h"
#include "sys/syscall.h"

_Noreturn void hydrogen_exit(void) {
    sched_exit();
}
