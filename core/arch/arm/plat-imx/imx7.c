// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm32.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <drivers/tzc380.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/misc.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <imx.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <util.h>

void plat_cpu_reset_late(void)
{
	uintptr_t addr;
	uint32_t val;

	if (get_core_pos() != 0)
		return;

	/*
	 * Configure imx7 CSU, first grant all peripherals
	 * TODO: fine tune the permissions
	 */
	for (addr = CSU_CSL_START; addr != CSU_CSL_END; addr += 4)
		write32(CSU_ACCESS_ALL, core_mmu_get_va(addr, MEM_AREA_IO_SEC));

	dsb();
	/* Protect OCRAM_S */
	write32(0x003300FF, core_mmu_get_va(CSU_CSL_59, MEM_AREA_IO_SEC));
	/* Proect TZASC */
	write32(0x00FF0033, core_mmu_get_va(CSU_CSL_28, MEM_AREA_IO_SEC));
	/*
	 * Proect CSU
	 * Note: Ater this settings, CSU seems still can be read,
	 * in non-secure world but can not be written.
	 */
	write32(0x00FF0033, core_mmu_get_va(CSU_CSL_15, MEM_AREA_IO_SEC));
	/*
	 * Protect SRC
	 * write32(0x003300FF, core_mmu_get_va(CSU_CSL_12, MEM_AREA_IO_SEC));
	 */
	dsb();

	/* lock the settings */
	for (addr = CSU_CSL_START; addr != CSU_CSL_END; addr += 4) {
		val = read32(core_mmu_get_va(addr, MEM_AREA_IO_SEC));
		write32(val | CSU_SETTING_LOCK,
			core_mmu_get_va(addr, MEM_AREA_IO_SEC));
	}
}
