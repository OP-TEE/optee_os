// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, HiSilicon Technologies Co., Ltd.
 * All rights reserved.
 */

#include <console.h>
#include <drivers/pl011.h>
#include <kernel/panic.h>
#include <mm/tee_pager.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static struct pl011_data console_data __nex_bss;

void plat_console_init(void)
{
	pl011_init(&console_data, UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);

	register_serial_console(&console_data.chip);
}