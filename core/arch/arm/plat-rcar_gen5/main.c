// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025-2026, Renesas Electronics Corporation.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/hfic.h>
#include <drivers/scif.h>
#include <kernel/boot.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(GICD_BASE, CORE_MMU_PGDIR_SIZE),
			ROUNDUP(GIC_DIST_REG_SIZE, CORE_MMU_PGDIR_SIZE));

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(MAP_DEV_REG_RCAR_BASE, CORE_MMU_PGDIR_SIZE),
			ROUNDUP(MAP_DEV_REG_RCAR_SIZE, CORE_MMU_PGDIR_SIZE));

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(NONCACHE_WORK_BASE, CORE_MMU_PGDIR_SIZE),
			ROUNDUP(NONCACHE_WORK_SIZE, CORE_MMU_PGDIR_SIZE));

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(OPTEE_LOG_BASE, CORE_MMU_PGDIR_SIZE),
			ROUNDUP(OPTEE_LOG_SIZE, CORE_MMU_PGDIR_SIZE));

static struct scif_uart_data console_data __nex_bss;

void boot_primary_init_intc(void)
{
#ifdef CFG_CORE_HAFNIUM_INTC
	hfic_init();
#else
	gic_init_v3(0, GICD_BASE, GICR_BASE);
#endif
}

#ifdef CFG_GIC
void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
#endif /* CFG_GIC */

void plat_console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
