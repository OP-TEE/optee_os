// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Pengutronix
 * All rights reserved.
 *
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <config.h>
#include <drivers/tzc380.h>
#include <imx-regs.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/generic_ram_layout.h>

/*
 * TZASC2_BASE is asserted non null when used.
 * This is needed to compile the code for i.MX6UL/L
 * and i.MX8MQ.
 */
#ifndef TZASC2_BASE
#define TZASC2_BASE			0
#endif

static TEE_Result imx_configure_tzasc(void)
{
	vaddr_t addr[2] = {0};
	int end = 1;
	int i = 0;

	addr[0] = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC, 1);

	if (IS_ENABLED(CFG_MX6Q) || IS_ENABLED(CFG_MX6D) ||
	    IS_ENABLED(CFG_MX6DL)) {
		assert(TZASC2_BASE != 0);
		addr[1] = core_mmu_get_va(TZASC2_BASE, MEM_AREA_IO_SEC, 1);
		end = 2;
	}

	for (i = 0; i < end; i++) {
		uint8_t region = 1;

		tzc_init(addr[i]);

		region = tzc_auto_configure(CFG_DRAM_BASE, CFG_DDR_SIZE,
			     TZC_ATTR_SP_NS_RW, region);
		region = tzc_auto_configure(CFG_TZDRAM_START, CFG_TZDRAM_SIZE,
			     TZC_ATTR_SP_S_RW, region);
		region = tzc_auto_configure(CFG_SHMEM_START, CFG_SHMEM_SIZE,
			     TZC_ATTR_SP_ALL, region);
		tzc_dump_state();
		if (tzc_regions_lockdown() != TEE_SUCCESS)
			panic("Region lockdown failed!");
	}
	return TEE_SUCCESS;
}
driver_init(imx_configure_tzasc);
