/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */
#ifndef __DRIVERS_SERIAL_H
#define __DRIVERS_SERIAL_H

#include <assert.h>
#include <stdbool.h>
#include <types_ext.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>

struct serial_chip {
	const struct serial_ops *ops;
};

struct serial_ops {
	void (*putc)(struct serial_chip *chip, int ch);
	void (*flush)(struct serial_chip *chip);
	bool (*have_rx_data)(struct serial_chip *chip);
	int (*getchar)(struct serial_chip *chip);
};

struct serial_driver {
	/* Allocate device data and return the inner serial_chip */
	struct serial_chip *(*dev_alloc)(void);
	/*
	 * Initialize device from FDT node. @parms is device-specific,
	 * its meaning is as defined by the DT bindings for the characters
	 * following the ":" in /chosen/stdout-path. Typically for UART
	 * devices this is <baud>{<parity>{<bits>{<flow>}}} where:
	 *   baud   - baud rate in decimal
	 *   parity - 'n' (none), 'o', (odd) or 'e' (even)
	 *   bits   - number of data bits
	 *   flow   - 'r' (rts)
	 * For example: 115200n8r
	 */
	int (*dev_init)(struct serial_chip *dev, const void *fdt,
			int offset, const char *parms);
	void (*dev_free)(struct serial_chip *dev);
};

#endif /*__DRIVERS_SERIASERIAL_H*/
