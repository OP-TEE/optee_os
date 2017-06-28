/*
 * Copyright (C) 2017 NXP
 * All rights reserved.
 *
 * Peng Fan <peng.fan@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

register_phys_mem(MEM_AREA_IO_SEC, SRC_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, IOMUXC_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, CCM_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, ANATOP_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GPC_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, DDRC_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, AIPS1_BASE, AIPS1_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, AIPS2_BASE, AIPS2_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, AIPS3_BASE, AIPS3_SIZE);

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
	 * Proect SRC
	 * write32(0x003300FF, get_base(CSU_CSL_12, MEM_AREA_IO_SEC));
	 */
	dsb();

	/* lock the settings */
	for (addr = CSU_CSL_START; addr != CSU_CSL_END; addr += 4) {
		val = read32(core_mmu_get_va(addr, MEM_AREA_IO_SEC));
		write32(val | CSU_SETTING_LOCK,
			core_mmu_get_va(addr, MEM_AREA_IO_SEC));
	}
}
