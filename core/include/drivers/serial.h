/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __DRIVERS_SERIAL_H
#define __DRIVERS_SERIAL_H

#include <stdbool.h>

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
