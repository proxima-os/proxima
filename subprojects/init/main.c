#include "hydrogen/sched.h"
#include "hydrogen/vfs.h"

__attribute__((used)) _Noreturn void _start(void) {
    hydrogen_write(1, "Hello from init!\n", 17);
    hydrogen_exit();
}
