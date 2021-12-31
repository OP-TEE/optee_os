/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __DRIVERS_HTIF_H__
#define __DRIVERS_HTIF_H__

#include <drivers/serial.h>
#include <types_ext.h>

#define HTIF_CMD_WRITE		1
#define HTIF_DEV_CONSOLE	1
#define HTIF_REG_SIZE	(2 * RISCV_XLEN_BYTES)

struct htif_console_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void htif_lock_global(void);
void htif_unlock_global(void);
void htif_console_init(struct htif_console_data *pd, paddr_t pbase);

#endif /*__DRIVERS_HTIF_H__*/
