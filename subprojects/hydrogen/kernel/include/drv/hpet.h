#ifndef HYDROGEN_DRV_HPET_H
#define HYDROGEN_DRV_HPET_H

#include <stdint.h>

extern uint64_t hpet_period_fs;

void init_hpet(void);

uint64_t read_hpet(void);

#endif // HYDROGEN_DRV_HPET_H
