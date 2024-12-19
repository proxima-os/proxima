#ifndef HYDROGEN_ASM_TABLES_H
#define HYDROGEN_ASM_TABLES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t limit;
    void *base;
} __attribute__((packed)) table_desc_t;

static inline void lgdt(void *base, size_t size) {
    table_desc_t desc = {size - 1, base};
    asm("lgdt %0" ::"m"(desc));
}

static inline void lidt(void *base, size_t size) {
    table_desc_t desc = {size - 1, base};
    asm("lidt %0" ::"m"(desc));
}

static inline void lldt(uint16_t selector) {
    asm("lldt %0" ::"r"(selector));
}

static inline void ltr(uint16_t selector) {
    asm("ltr %0" ::"r"(selector));
}

#endif // HYDROGEN_ASM_TABLES_H
