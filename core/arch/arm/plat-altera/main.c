// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Altera Corporation.
 */

#include <console.h>
#include <drivers/serial8250_uart.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include "platform_config.h"

static struct serial8250_uart_data uart_console;

void plat_console_init(void)
{
	serial8250_uart_init(&uart_console,
			     CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ,
			     CONSOLE_BAUDRATE);
	register_serial_console(&uart_console.chip);
}

/* Map UART registers as I/O memory */
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			SERIAL8250_UART_REG_SIZE);

/* Register main DDR for dynamic shared memory */
register_ddr(DRAM0_BASE, DRAM0_SIZE);
