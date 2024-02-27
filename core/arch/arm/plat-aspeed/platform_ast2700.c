// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Aspeed Technology Inc.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <io.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

register_phys_mem(MEM_AREA_IO_SEC, UART_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICR_BASE, GICR_SIZE);

register_ddr(CFG_DRAM_BASE, CFG_DRAM_SIZE);

static struct serial8250_uart_data console_data;

void boot_primary_init_intc(void)
{
	gic_init_v3(0, GICD_BASE, GICR_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

void plat_console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
