// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, EPAM Systems.
 */

#include <console.h>
#include <drivers/pl011.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CONSOLE_UART_BASE, PL011_REG_SIZE);

static struct pl011_data console_data __nex_bss;

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
