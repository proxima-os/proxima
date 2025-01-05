#ifndef HYDROGEN_VFS_H
#define HYDROGEN_VFS_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HYDROGEN_WHENCE_SET,
    HYDROGEN_WHENCE_CUR,
    HYDROGEN_WHENCE_END,
} hydrogen_whence_t;

typedef struct {
    size_t transferred;
    int error;
} hydrogen_io_res_t;

int hydrogen_seek(int fd, uint64_t *offset, hydrogen_whence_t whence);
hydrogen_io_res_t hydrogen_read(int fd, void *buffer, size_t size);
hydrogen_io_res_t hydrogen_write(int fd, const void *buffer, size_t size);
hydrogen_io_res_t hydrogen_pread(int fd, void *buffer, size_t size, uint64_t position);
hydrogen_io_res_t hydrogen_pwrite(int fd, const void *buffer, size_t size, uint64_t position);

#endif // HYDROGEN_VFS_H
