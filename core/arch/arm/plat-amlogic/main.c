// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Carlo Caione <ccaione@baylibre.com>
 */

#include <console.h>
#include <drivers/amlogic_uart.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static struct amlogic_uart_data console_data;
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);

void console_init(void)
{
	amlogic_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
