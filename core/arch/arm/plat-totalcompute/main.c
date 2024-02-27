// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>

#include <mm/core_mmu.h>
#include <platform_config.h>

static struct pl011_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
#ifndef CFG_CORE_SEL2_SPMC
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

#ifndef CFG_CORE_SEL2_SPMC
void boot_primary_init_intc(void)
{
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICC_OFFSET);
}
#endif

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_UART_BAUDRATE);
	register_serial_console(&console_data.chip);
}
