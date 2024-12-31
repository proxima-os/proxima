#ifndef HYDROGEN_CPU_IRQVEC_H
#define HYDROGEN_CPU_IRQVEC_H

#define IRQ_DEV_MIN 0x20
#define IRQ_DEV_MAX 0xf0
#define IRQ_TIMER 0xfa
#define IPI_SHOOTDOWN 0xfb
#define IPI_RESCHEDULE 0xfc
#define IPI_PANIC 0xfd
#define IRQ_APIC_ERR 0xfe
#define IRQ_SPURIOUS 0xff

#endif // HYDROGEN_CPU_IRQVEC_H
