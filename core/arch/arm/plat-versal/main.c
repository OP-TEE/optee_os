// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

static struct gic_data gic_data;
static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			GIC_BASE, CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			GIC_BASE + GICD_OFFSET, CORE_MMU_PGDIR_SIZE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);

#if defined(DRAM1_BASE)
register_ddr(DRAM1_BASE, DRAM1_SIZE);
register_ddr(DRAM2_BASE, DRAM2_SIZE);
#endif

void main_init_gic(void)
{
	/* On ARMv8, GIC configuration is initialized in ARM-TF */
	gic_init_base_addr(&gic_data,
			   GIC_BASE + GICC_OFFSET,
			   GIC_BASE + GICD_OFFSET);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		   CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
