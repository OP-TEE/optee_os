// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Pengutronix
 * All rights reserved.
 * Copyright 2019 NXP
 *
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <drivers/tzc380.h>
#include <imx-regs.h>
#include <imx.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/generic_ram_layout.h>

void imx_configure_tzasc(void)
{
	uint8_t region;
	vaddr_t addr[2] = { 0 };
	uint8_t tzc_controllers = 1;
	uint8_t i;

	addr[0] = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC);

	if (!addr[0])
		panic("Cannot get TZASC1 base address");

#ifdef TZASC2_BASE
	addr[1] = core_mmu_get_va(TZASC2_BASE, MEM_AREA_IO_SEC);

	if (!addr[1])
		panic("Cannot get TZASC2 base address");

	tzc_controllers = 2;
#endif

	for (i = 0; i < tzc_controllers; i++) {
		region = 1;

		tzc_init(addr[i]);

		region = tzc_auto_configure(CFG_TZC_NSEC_START, CFG_DDR_SIZE,
					    TZC_ATTR_SP_NS_RW, region);
		region = tzc_auto_configure(CFG_TZC_SEC_START, CFG_TZDRAM_SIZE,
					    TZC_ATTR_SP_S_RW, region);
		region = tzc_auto_configure(CFG_TZC_SHMEM_START, CFG_SHMEM_SIZE,
					    TZC_ATTR_SP_ALL, region);

		DMSG("Action register: 0x%" PRIx32, tzc_get_action());
	}
}
