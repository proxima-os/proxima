#ifndef HYDROGEN_ASM_PIO_H
#define HYDROGEN_ASM_PIO_H

#include <stdint.h>

static inline void outb(uint16_t port, uint8_t value) {
    asm("outb %0, %1" ::"a"(value), "Nd"(port) : "memory");
}

static inline void outw(uint16_t port, uint16_t value) {
    asm("outw %0, %1" ::"a"(value), "Nd"(port) : "memory");
}

static inline void outl(uint16_t port, uint32_t value) {
    asm("outl %0, %1" ::"a"(value), "Nd"(port) : "memory");
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    asm volatile("inw %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    asm volatile("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

#endif // HYDROGEN_ASM_PIO_H
