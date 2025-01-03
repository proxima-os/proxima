#ifndef HYDROGEN_ASM_IDLE_H
#define HYDROGEN_ASM_IDLE_H

static inline void cpu_idle(void) {
    asm("hlt");
}

static inline void cpu_relax(void) {
    __builtin_ia32_pause();
}

#endif // HYDROGEN_ASM_IDLE_H
