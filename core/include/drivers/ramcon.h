/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DRIVERS_RAMCON_H
#define __DRIVERS_RAMCON_H

#include <drivers/serial.h>
#include <types_ext.h>

/*
 * Ring-buffer console in size bytes of RAM at physical address base, 16 of
 * them header: u64 magic "RAMCON", u64 head. Read it from the normal world.
 * The platform maps the window as MEM_AREA_IO_NSEC.
 */
struct ramcon_data {
	struct io_pa_va base;
	size_t size;
	struct serial_chip chip;
};

void ramcon_init(struct ramcon_data *pd, paddr_t base, size_t size);

#endif /* __DRIVERS_RAMCON_H */
