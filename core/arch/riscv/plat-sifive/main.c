// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 SiFive, Inc
 */

#include <console.h>
#include <drivers/sifive_uart.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CONSOLE_UART_BASE, SIFIVE_UART_REG_SIZE);

static struct sifive_uart_data console_data;

void plat_console_init(void)
{
	sifive_uart_init(&console_data, CONSOLE_UART_BASE,
			 CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);

	register_serial_console(&console_data.chip);
}
