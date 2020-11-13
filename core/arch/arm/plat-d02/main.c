// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <console.h>
#include <drivers/hi16xx_uart.h>
#include <kernel/panic.h>
#include <mm/tee_pager.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static struct hi16xx_uart_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			HI16XX_UART_REG_SIZE);

void console_init(void)
{
	hi16xx_uart_init(&console_data, CONSOLE_UART_BASE,
			 CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
