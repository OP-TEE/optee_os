// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

static struct gic_data gic_data;

#if defined(CFG_EARLY_CONSOLE)
static struct serial8250_uart_data early_console_data;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CFG_EARLY_CONSOLE_BASE, CFG_EARLY_CONSOLE_SIZE);
#endif

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);

void main_init_gic(void)
{
	vaddr_t gicc_base = 0;
	vaddr_t gicd_base = 0;

#if !defined(CFG_ARM_GICV3)
	gicc_base = (vaddr_t)phys_to_virt(GICC_BASE, MEM_AREA_IO_SEC);
	if (!gicc_base)
		panic();
#endif

	gicd_base = (vaddr_t)phys_to_virt(GICD_BASE, MEM_AREA_IO_SEC);
	if (!gicd_base)
		panic();

	/* Initialize GIC */
	gic_init(&gic_data, gicc_base, gicd_base);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

void console_init(void)
{
#if defined(CFG_EARLY_CONSOLE)
	/*
	 * Console devices can vary a lot between devices and
	 * OP-TEE will switch to the DT-based real console later,
	 * based on DT-devices and the systems chosen node.
	 * So early console is only needed for early debugging.
	 */
	serial8250_uart_init(&early_console_data,
			     CFG_EARLY_CONSOLE_BASE,
			     CFG_EARLY_CONSOLE_CLK_IN_HZ,
			     CFG_EARLY_CONSOLE_BAUDRATE);
	register_serial_console(&early_console_data.chip);
#endif
}
