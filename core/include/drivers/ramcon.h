/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DRIVERS_RAMCON_H
#define __DRIVERS_RAMCON_H

#include <drivers/serial.h>

/*
 * Ring-buffer console at CFG_RAMCON_BASE (CFG_RAMCON_SIZE bytes, 16 of them
 * header: u64 magic "RAMCON", u64 head). Read it from the normal world.
 */
struct ramcon_data {
	struct serial_chip chip;
};

void ramcon_init(struct ramcon_data *pd);

#endif /* __DRIVERS_RAMCON_H */
