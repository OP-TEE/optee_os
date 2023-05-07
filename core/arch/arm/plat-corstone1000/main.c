// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Arm Limited
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

static struct gic_data gic_data __nex_bss;
static struct pl011_data console_data __nex_bss;

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(MM_COMM_BUF_BASE, MM_COMM_BUF_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);

void main_init_gic(void)
{
	gic_init_base_addr(&gic_data, GICC_BASE, GICD_BASE);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
