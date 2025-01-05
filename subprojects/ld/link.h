#ifndef LD_LINK_H
#define LD_LINK_H

#include <stdint.h>

extern const void *vdso_image;

void setup_vdso(void);

void link_self(uintptr_t base);

#endif // LD_LINK_H
