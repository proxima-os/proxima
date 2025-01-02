#ifndef HYDROGEN_CPU_EXC_H
#define HYDROGEN_CPU_EXC_H

#include "cpu/idt.h"

void init_exc(void);

void handle_fatal_exception(idt_frame_t *frame);

#endif // HYDROGEN_CPU_EXC_H
