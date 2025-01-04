#ifndef HYDROGEN_ASM_SMAP_H
#define HYDROGEN_ASM_SMAP_H

static inline void enable_user_access(void) {
    asm("stac");
}

static inline void disable_user_access(void) {
    asm("clac");
}

#endif // HYDROGEN_ASM_SMAP_H
