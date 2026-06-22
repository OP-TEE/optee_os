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
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <trace.h>
#include "topology.h"

static struct pl011_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(CONSOLE_UART_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICR_BASE, GIC_DIST_REG_SIZE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);

void boot_primary_init_intc(void)
{
#if defined(CFG_PLAT_DYN_CLUSTER)
	/*
	 * Set plat_cluster_shift from the DTB *before* gic_init_v3()
	 * calls probe_redist_base_addrs().  That function uses
	 * get_core_pos_mpidr() to map each GICR frame to a core slot; if
	 * the shift is wrong at that point, frames for cores in higher
	 * clusters get positions >= CFG_TEE_CORE_NB_CORE and are silently
	 * dropped.  The external DT is already mapped by the time this
	 * function is called (init_external_dt runs earlier in
	 * boot_init_primary_late).  A NULL return from get_external_dt()
	 * is handled gracefully: topology falls back to the compile-time
	 * default (CFG_CORE_CLUSTER_SHIFT).
	 */
	plat_topology_early_init(get_external_dt());
#endif
	gic_init_v3(0, GICD_BASE, GICR_BASE);
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

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}
