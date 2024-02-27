// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#if (CFG_TEE_CORE_LOG_LEVEL != 0)
register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CONSOLE_UART_BASE, SERIAL8250_UART_REG_SIZE);
#endif

static struct serial8250_uart_data console_data;

register_ddr(CFG_DRAM_BASE, CFG_DRAM_SIZE);

#ifdef CFG_GIC
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE + GICD_OFFSET,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE + GICC_OFFSET,
			CORE_MMU_PGDIR_SIZE);

void boot_primary_init_intc(void)
{
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
}
#endif

void plat_console_init(void)
{
	if (CFG_TEE_CORE_LOG_LEVEL != 0) {
		serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
				     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
		register_serial_console(&console_data.chip);
	}
}
