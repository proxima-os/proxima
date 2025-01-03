#ifndef HYDROGEN_CPU_IDT_H
#define HYDROGEN_CPU_IDT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t rax;
    size_t rbx;
    size_t rcx;
    size_t rdx;
    size_t rsi;
    size_t rdi;
    size_t rbp;
    size_t r8;
    size_t r9;
    size_t r10;
    size_t r11;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
    size_t vector;
    size_t error_code;
    size_t rip;
    size_t cs;
    size_t rflags;
    size_t rsp;
    size_t ss;
} __attribute__((aligned(16), packed)) idt_frame_t;

typedef void (*idt_handler_t)(idt_frame_t *frame);

void init_idt(void);

void load_idt(void);

void idt_install(uint8_t vector, idt_handler_t handler);

void idt_uninstall(uint8_t vector, idt_handler_t handler);

bool paranoid_enter(idt_frame_t *frame);

void paranoid_exit(bool swapped);

#endif // HYDROGEN_CPU_IDT_H
