#pragma once

#include <stddef.h>
#include <stdint.h>

static inline uint8_t mmio_read8(uintptr_t base, size_t offset) {
    uint8_t value;
    asm volatile("movb %1, %0" : "=a"(value) : "m"(*(volatile uint8_t *)(base + offset)) : "memory");
    return value;
}

static inline uint16_t mmio_read16(uintptr_t base, size_t offset) {
    uint16_t value;
    asm volatile("movw %1, %0" : "=a"(value) : "m"(*(volatile uint16_t *)(base + offset)) : "memory");
    return value;
}

static inline uint32_t mmio_read32(uintptr_t base, size_t offset) {
    uint32_t value;
    asm volatile("movl %1, %0" : "=a"(value) : "m"(*(volatile uint32_t *)(base + offset)) : "memory");
    return value;
}

static inline uint64_t mmio_read64(uintptr_t base, size_t offset) {
    uint64_t value;
    asm volatile("movq %1, %0" : "=a"(value) : "m"(*(volatile uint64_t *)(base + offset)) : "memory");
    return value;
}

static inline void mmio_write8(uintptr_t base, size_t offset, uint8_t value) {
    asm("movb %0, %1" ::"a"(value), "m"(*(volatile uint8_t *)(base + offset)) : "memory");
}

static inline void mmio_write16(uintptr_t base, size_t offset, uint16_t value) {
    asm("movw %0, %1" ::"a"(value), "m"(*(volatile uint16_t *)(base + offset)) : "memory");
}

static inline void mmio_write32(uintptr_t base, size_t offset, uint32_t value) {
    asm("movl %0, %1" ::"a"(value), "m"(*(volatile uint32_t *)(base + offset)) : "memory");
}

static inline void mmio_write64(uintptr_t base, size_t offset, uint64_t value) {
    asm("movq %0, %1" ::"a"(value), "m"(*(volatile uint64_t *)(base + offset)) : "memory");
}
