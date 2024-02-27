// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2022, Huawei Technologies Co., Ltd
 */
#include <console.h>
#include <drivers/lpc_uart.h>
#include <platform_config.h>

static struct lpc_uart_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, LPC_BASE, LPC_SIZE);

void plat_console_init(void)
{
	lpc_uart_init(&console_data, LPC_BASE, CONSOLE_UART_CLK_IN_HZ,
		      CONSOLE_BAUDRATE);

	register_serial_console(&console_data.chip);
}
