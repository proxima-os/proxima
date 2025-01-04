#ifndef HYDROGEN_INIT_INITRD_H
#define HYDROGEN_INIT_INITRD_H

#include "fs/vfs.h"
#include <stddef.h>

void extract_initrds(file_t *rel, const char *path, size_t length);

#endif // HYDROGEN_INIT_INITRD_H
