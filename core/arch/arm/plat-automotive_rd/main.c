// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 - 2025, Arm Limited
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

static struct pl011_data console_data __nex_bss;

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, PL011_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);

#if defined(PLATFORM_FLAVOR_rd1ae)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);
#endif

#if defined(PLATFORM_FLAVOR_rdaspen)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE, GICR_SIZE);
#endif

void boot_primary_init_intc(void)
{
#if defined(PLATFORM_FLAVOR_rd1ae)
	gic_init(GICC_BASE, GICD_BASE);
#endif

#if defined(PLATFORM_FLAVOR_rdaspen)
	/* GICC_BASE is not required for GICv3 */
	gic_init_v3(0, GICD_BASE, GICR_BASE);
#endif
}

#if defined(PLATFORM_FLAVOR_rd1ae)
void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
#endif

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
