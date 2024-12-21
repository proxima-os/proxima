#ifndef HYDROGEN_MEM_VHEAP_H
#define HYDROGEN_MEM_VHEAP_H

#include <stddef.h>

void *vmalloc(size_t size);

void vmfree(void *ptr, size_t size);

#endif // HYDROGEN_MEM_VHEAP_H
