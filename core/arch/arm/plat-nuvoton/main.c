// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2023, Linaro Limited
 * Copyright (c) 2014-2023, STMicroelectronics International N.V.
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/ns16550.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <platform_config.h>
#include <trace.h>

#define COLOR_NORMAL	"\x1B[0m"
#define COLOR_RED	"\x1B[31m"
#define COLOR_GREEN	"\x1B[32m"
#define COLOR_YELLOW	"\x1B[33m"
#define COLOR_BLUE	"\x1B[34m"
#define COLOR_MAGENTA	"\x1B[35m"
#define COLOR_CYAN	"\x1B[36m"
#define COLOR_WHITE	"\x1B[37m"

static struct ns16550_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, UART_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);

static void print_version(void)
{
	IMSG(COLOR_MAGENTA);
	IMSG(">================================================");
	IMSG("OP-TEE OS Version %s", core_v_str);
	IMSG(">================================================");
	IMSG(COLOR_NORMAL);
}

void primary_init_intc(void)
{
	if (IS_ENABLED(CFG_NPCM_DEBUG))
		print_version();

	gic_init(GICC_BASE, GICD_BASE);
}

void console_init(void)
{
	ns16550_init(&console_data, CONSOLE_UART_BASE, IO_WIDTH_U32, 2);
	register_serial_console(&console_data.chip);
}
