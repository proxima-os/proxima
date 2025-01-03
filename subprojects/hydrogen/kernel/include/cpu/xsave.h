#ifndef HYDROGEN_CPU_XSAVE_H
#define HYDROGEN_CPU_XSAVE_H

void init_xsave_bsp(void);

void init_xsave_ap(void);

void *alloc_xsave(void);

void free_xsave(void *ptr);

// Saves extended registers to current_task->xsave_area
void xsave(void);

// Restores extended registers from current_task->xsave_area
void xrestore(void);

// Resets all extended registers to their default values
void xreset(void);

#endif // HYDROGEN_CPU_XSAVE_H
