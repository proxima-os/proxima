#ifndef HYDROGEN_CPU_CPU_H
#define HYDROGEN_CPU_CPU_H

#include <stdbool.h>

extern bool pg_supported;
extern bool nx_supported;
extern bool gb_pages_supported;
extern bool tsc_supported;
extern bool tsc_deadline_supported;
extern bool running_in_hypervisor;
extern bool tsc_invariant;
extern bool xsave_supported;
extern bool fsgsbase_supported;
extern bool smap_supported;

void init_cpu(void);

#endif // HYDROGEN_CPU_CPU_H
