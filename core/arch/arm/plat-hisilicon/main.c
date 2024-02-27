// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, HiSilicon Technologies Co., Ltd.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <kernel/panic.h>
#include <mm/tee_pager.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static struct pl011_data console_data;
register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
#ifdef BOOTSRAM_BASE
register_phys_mem(MEM_AREA_IO_SEC, BOOTSRAM_BASE, BOOTSRAM_SIZE);
#endif
#ifdef CPU_CRG_BASE
register_phys_mem(MEM_AREA_IO_SEC, CPU_CRG_BASE, CPU_CRG_SIZE);
#endif
#ifdef SYS_CTRL_BASE
register_phys_mem(MEM_AREA_IO_SEC, SYS_CTRL_BASE, SYS_CTRL_SIZE);
#endif

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
