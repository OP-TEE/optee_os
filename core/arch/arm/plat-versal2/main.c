// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <arm.h>
#include <assert.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <drivers/versal_pm.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/misc.h>
#include <kernel/tee_time.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <trace.h>

static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE, GIC_DIST_REG_SIZE);

#if defined(CFG_RPMB_FS)
register_phys_mem(MEM_AREA_IO_SEC, PLAT_SST_BASE, PLAT_SST_LEN);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);

/*
 * Read GIC base addresses from the GIC node's reg property in the DTB.
 * The reg property layout for arm,gic-v3 (2 address-cells, 2 size-cells):
 *   [0][1] = GICD addr   [2][3] = GICD size
 *   [4][5] = GICR addr   [6][7] = GICR size
 *
 * Falls back to compile-time GICD_BASE/GICR_BASE if DTB is unavailable
 * or malformed.
 */
static void get_gic_bases_from_dt(const void *fdt, paddr_t *gicd_base,
				  paddr_t *gicr_base)
{
	const fdt32_t *reg = NULL;
	int node = 0;
	int len = 0;

	*gicd_base = GICD_BASE;
	*gicr_base = GICR_BASE;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,gic-v3");
	if (node < 0)
		return;

	reg = fdt_getprop(fdt, node, "reg", &len);
	if (!reg || len < (int)(8 * sizeof(fdt32_t)))
		return;

	*gicd_base = ((paddr_t)fdt32_to_cpu(reg[0]) << 32) |
		     fdt32_to_cpu(reg[1]);
	*gicr_base = ((paddr_t)fdt32_to_cpu(reg[4]) << 32) |
		     fdt32_to_cpu(reg[5]);
}

void boot_primary_init_intc(void)
{
	const void *fdt = get_external_dt();
	paddr_t gicd_base = GICD_BASE;
	paddr_t gicr_base = GICR_BASE;

	if (fdt) {
		get_gic_bases_from_dt(fdt, &gicd_base, &gicr_base);
		if (gicd_base != GICD_BASE)
			IMSG("GICD base overridden by DTB: 0x%016lx",
			     (unsigned long)gicd_base);
		if (gicr_base != GICR_BASE)
			IMSG("GICR base overridden by DTB: 0x%016lx",
			     (unsigned long)gicr_base);
	} else {
		IMSG("External DT not found");
	}

	DMSG("GICD base: 0x%016lx GICR base: 0x%016lx",
	     (unsigned long)gicd_base, (unsigned long)gicr_base);
	gic_init_v3(0, gicd_base, gicr_base);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

void plat_console_init(void)
{
	pl011_init(&console_data, CONSOLE_UART_BASE,
		   CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

static TEE_Result platform_banner(void)
{
	IMSG("OP-TEE OS Running on Platform AMD Versal Gen 2");

	return TEE_SUCCESS;
}

service_init(platform_banner);
