// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Carlo Caione <ccaione@baylibre.com>
 */

#include <console.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <drivers/amlogic_uart.h>

static const struct thread_handlers handlers = {
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static struct amlogic_uart_data console_data;
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);

void console_init(void)
{
	amlogic_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
