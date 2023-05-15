// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019, 2023 NXP
 *
 */

#include <imx.h>
#include <initcall.h>
#include <io.h>
#include <kernel/tz_ssvce_def.h>
#include <mm/core_memprot.h>

/* Invalidate all registers */
#define	SCU_INV_CTRL_INIT	0xFFFFFFFF
/* Both secure CPU access SCU */
#define SCU_SAC_CTRL_INIT	0x0000000F
/* Both non-secure CPU access SCU, private and global timer */
#define SCU_NSAC_CTRL_INIT	0x00000FFF

static TEE_Result scu_init(void)
{
	vaddr_t scu_base = core_mmu_get_va(SCU_BASE, MEM_AREA_IO_SEC,
					   SCU_SIZE);

	if (!scu_base)
		return TEE_ERROR_GENERIC;

	/* SCU config */
	io_write32(scu_base + SCU_INV_SEC, SCU_INV_CTRL_INIT);
	io_write32(scu_base + SCU_SAC, SCU_SAC_CTRL_INIT);
	io_write32(scu_base + SCU_NSAC, SCU_NSAC_CTRL_INIT);

	/* SCU enable */
	io_write32(scu_base + SCU_CTRL, io_read32(scu_base + SCU_CTRL) | 0x1);

	return TEE_SUCCESS;
}
driver_init(scu_init);
