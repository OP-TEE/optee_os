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
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>

#include <mm/core_mmu.h>
#include <platform_config.h>

#ifndef CFG_CORE_SEL2_SPMC
static struct gic_data gic_data __nex_bss;
#endif
static struct pl011_data console_data __nex_bss;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
#ifndef CFG_CORE_SEL2_SPMC
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

#ifndef CFG_CORE_SEL2_SPMC
void main_init_gic(void)
{
	vaddr_t gicc_base;

	gicc_base = (vaddr_t)phys_to_virt(GIC_BASE + GICC_OFFSET,
					  MEM_AREA_IO_SEC);
	if (!gicc_base)
		panic();

	/*
	 * On ARMv8, GIC configuration is initialized in ARM-TF
	 * gicd base address is same as gicc_base.
	 */
	gic_init_base_addr(&gic_data, gicc_base, gicc_base);
	itr_init(&gic_data.chip);
}
#endif

void itr_core_handler(void)
{
#ifdef CFG_CORE_SEL2_SPMC
	panic("Secure interrupt handler not defined");
#else
	gic_it_handle(&gic_data);
#endif
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_UART_BAUDRATE);
	register_serial_console(&console_data.chip);
}
