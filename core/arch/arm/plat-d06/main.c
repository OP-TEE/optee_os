// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2022, Huawei Technologies Co., Ltd
 */
#include <console.h>
#include <drivers/lpc_uart.h>
#include <drivers/pl011.h>
#include <platform_config.h>

#if defined(PLATFORM_FLAVOR_d06)
static struct lpc_uart_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, LPC_BASE, LPC_SIZE);
#endif

#if defined(PLATFORM_FLAVOR_HIP08A)
static struct pl011_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART_BASE, PL011_REG_SIZE);
#endif

register_phys_mem_pgdir(MEM_AREA_IO_SEC, HISI_SEC_BASE, HISI_SEC_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, HISI_TRNG_BASE, HISI_TRNG_SIZE);

void plat_console_init(void)
{
#if defined(PLATFORM_FLAVOR_d06)
	lpc_uart_init(&console_data, LPC_BASE, CONSOLE_UART_CLK_IN_HZ,
		      CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
#endif

#if defined(PLATFORM_FLAVOR_HIP08A)
	pl011_init(&console_data, UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
#endif
}
