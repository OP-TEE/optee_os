// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, HiSilicon Technologies Co., Ltd.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/tee_pager.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

static const struct thread_handlers handlers = {
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

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

const struct thread_handlers *boot_get_handlers(void)
{
	return &handlers;
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
