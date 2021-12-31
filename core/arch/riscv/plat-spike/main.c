// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <console.h>
#include <platform_config.h>

#include "drivers/htif.h"

static struct htif_console_data console_data __nex_bss;

void console_init(void)
{
#ifdef HTIF_BASE
	htif_console_init(&console_data, HTIF_BASE);
	register_serial_console(&console_data.chip);
#endif
}
