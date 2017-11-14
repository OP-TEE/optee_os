// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/tz_ssvce_pl310.h>

#include <imx.h>
#include <imx-regs.h>

void scu_init(void)
{
	vaddr_t scu_base = core_mmu_get_va(SCU_BASE, MEM_AREA_IO_SEC);

	/* SCU config */
	write32(SCU_INV_CTRL_INIT,  scu_base + SCU_INV_SEC);
	write32(SCU_SAC_CTRL_INIT,  scu_base + SCU_SAC);
	write32(SCU_NSAC_CTRL_INIT, scu_base + SCU_NSAC);

	/* SCU enable */
	write32(read32(scu_base + SCU_CTRL) | 0x1, scu_base + SCU_CTRL);
}

