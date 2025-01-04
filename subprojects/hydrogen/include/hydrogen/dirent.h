#ifndef HYDROGEN_DIRENT_H
#define HYDROGEN_DIRENT_H

#include <stddef.h>
#include <stdint.h>

#define DT_UNKNOWN 0
#define DT_DIR 1
#define DT_LNK 2
#define DT_REG 3
#define DT_CHR 4
#define DT_BLK 5
#define DT_FIFO 6
#define DT_SOCK 7

typedef struct {
    uint64_t id;
    uint64_t pos;  // the value to pass to seek(SEEK_SET) to read this entry again (this is not guaranteed to work)
    size_t length; // length of the `name` field
    unsigned char kind;
    char name[]; // not zero-terminated
} hydrogen_dirent_t;

#endif // HYDROGEN_DIRENT_H
