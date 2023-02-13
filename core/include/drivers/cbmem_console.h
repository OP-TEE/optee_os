/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Linaro Limited
 */
#ifndef CBMEM_CONSOLE_H
#define CBMEM_CONSOLE_H

#include <types_ext.h>
#include <drivers/serial.h>

struct cbmem_console {
	uint32_t size;
	uint32_t cursor;
	uint8_t body[0];
} __packed;

struct cbmem_console_data {
	paddr_t base;
	struct cbmem_console *console;
	struct serial_chip chip;
	uint32_t size;
};

bool cbmem_console_init_from_dt(void *fdt);

#endif /* CBMEM_CONSOLE_H */

