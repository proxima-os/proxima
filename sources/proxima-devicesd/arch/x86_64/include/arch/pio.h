#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint16_t pio_addr_t;

#define ARCH_HAS_PIO 1
#define ARCH_PIO_MAX UINT16_MAX

static inline uint8_t pio_read8(pio_addr_t address) {
    uint8_t value;
    asm volatile("inb %1, %0" : "=a"(value) : "Nd"(address) : "memory");
    return value;
}

static inline uint16_t pio_read16(pio_addr_t address) {
    uint16_t value;
    asm volatile("inw %1, %0" : "=a"(value) : "Nd"(address) : "memory");
    return value;
}

static inline uint32_t pio_read32(pio_addr_t address) {
    uint32_t value;
    asm volatile("inl %1, %0" : "=a"(value) : "Nd"(address) : "memory");
    return value;
}

static inline void pio_write8(pio_addr_t address, uint8_t value) {
    asm("outb %0, %1" ::"a"(value), "Nd"(address) : "memory");
}

static inline void pio_write16(pio_addr_t address, uint16_t value) {
    asm("outw %0, %1" ::"a"(value), "Nd"(address) : "memory");
}

static inline void pio_write32(pio_addr_t address, uint32_t value) {
    asm("outl %0, %1" ::"a"(value), "Nd"(address) : "memory");
}

static inline void pio_read8_n(pio_addr_t address, uint8_t *buffer, size_t count) {
    asm volatile("rep insb" : "+D"(buffer), "+c"(count) : "d"(address) : "memory");
}

static inline void pio_read16_n(pio_addr_t address, uint16_t *buffer, size_t count) {
    asm volatile("rep insw" : "+D"(buffer), "+c"(count) : "d"(address) : "memory");
}

static inline void pio_read32_n(pio_addr_t address, uint32_t *buffer, size_t count) {
    asm volatile("rep insl" : "+D"(buffer), "+c"(count) : "d"(address) : "memory");
}

static inline void pio_write8_n(pio_addr_t address, const uint8_t *data, size_t count) {
    asm volatile("rep outsb" : "+S"(data), "+c"(count) : "d"(address) : "memory");
}

static inline void pio_write16_n(pio_addr_t address, const uint16_t *data, size_t count) {
    asm volatile("rep outsw" : "+S"(data), "+c"(count) : "d"(address) : "memory");
}

static inline void pio_write32_n(pio_addr_t address, const uint32_t *data, size_t count) {
    asm volatile("rep outsl" : "+S"(data), "+c"(count) : "d"(address) : "memory");
}
