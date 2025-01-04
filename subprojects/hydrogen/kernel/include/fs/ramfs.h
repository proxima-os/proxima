#ifndef HYDROGEN_FS_RAMFS_H
#define HYDROGEN_FS_RAMFS_H

#include "fs/vfs.h"

int ramfs_create(vfs_t **out, uint32_t mode, ident_t *ident);

#endif // HYDROGEN_FS_RAMFS_H
