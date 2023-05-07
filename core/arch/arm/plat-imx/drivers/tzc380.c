// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Pengutronix
 * All rights reserved.
 * Copyright 2023 NXP
 *
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <config.h>
#include <drivers/tzc380.h>
#include <imx-regs.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <mm/core_memprot.h>
#include <mm/generic_ram_layout.h>

/*
 * TZASC2_BASE is asserted non null when used.
 * This is needed to compile the code for i.MX6UL/L
 * and i.MX8MQ.
 */
#ifndef TZASC2_BASE
#define TZASC2_BASE			0
#else
register_phys_mem(MEM_AREA_IO_SEC, TZASC2_BASE, TZASC_SIZE);
#endif

register_phys_mem(MEM_AREA_IO_SEC, TZASC_BASE, TZASC_SIZE);

static int imx_tzc_auto_configure(vaddr_t addr, vaddr_t rsize, uint32_t attr,
				  uint8_t region)
{
	vaddr_t addr_imx = 0;

	/*
	 * On 8mscale platforms, the TZASC controller for the DRAM protection,
	 * has the memory regions starting at address 0x0 instead of the DRAM
	 * base address (0x40000000)
	 */
	if (IS_ENABLED(CFG_MX8M))
		addr_imx = addr - CFG_DRAM_BASE;
	else
		addr_imx = addr;

	return tzc_auto_configure(addr_imx, rsize, attr, region);
}

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

		region = imx_tzc_auto_configure(CFG_DRAM_BASE, CFG_DDR_SIZE,
						TZC_ATTR_SP_NS_RW, region);
		region = imx_tzc_auto_configure(CFG_TZDRAM_START,
						CFG_TZDRAM_SIZE,
						TZC_ATTR_SP_S_RW, region);
		region = imx_tzc_auto_configure(CFG_SHMEM_START, CFG_SHMEM_SIZE,
						TZC_ATTR_SP_ALL, region);

		if (tzc_regions_lockdown() != TEE_SUCCESS)
			panic("Region lockdown failed!");

		tzc_dump_state();
	}
	return TEE_SUCCESS;
}

static TEE_Result
pm_enter_resume(enum pm_op op, uint32_t pm_hint __unused,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_RESUME)
		return imx_configure_tzasc();

	return TEE_SUCCESS;
}

static TEE_Result tzasc_init(void)
{
	register_pm_driver_cb(pm_enter_resume, NULL, "imx-tzasc");

	return imx_configure_tzasc();
}
driver_init(tzasc_init);
