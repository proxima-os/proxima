#ifndef HYDROGEN_SYS_SYSVECS_H
#define HYDROGEN_SYS_SYSVECS_H

#include <stddef.h>

typedef struct {
    union {
        size_t num;
        void *ptr;
    } value;
    int error;
} syscall_result_t;

#define SYS_EXIT 0ul
#define SYS_MMAP 1ul
#define SYS_MPROTECT 2ul
#define SYS_MUNMAP 3ul
#define SYS_PRINT 4ul

#endif // HYDROGEN_SYS_SYSVECS_H
