// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Google LLC
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			SERIAL8250_UART_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE,
			GIC_REDIST_REG_SIZE * CFG_TEE_CORE_NB_CORE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

static struct serial8250_uart_data console_data __nex_bss;

void plat_console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

void boot_primary_init_intc(void)
{
	gic_init_v3(0, GICD_BASE, GICR_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
