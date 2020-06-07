/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <console.h>
#include <drivers/pl011.h>
#ifdef CFG_PL061
#include <drivers/pl061_gpio.h>
#endif
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
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
/* for dynamic shared memory */
register_dynamic_shm(DRAM0_BASE_NSEC, DRAM0_SIZE_NSEC);

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
