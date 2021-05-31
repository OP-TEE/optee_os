// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * Brief   CAAM Clock functions.
 */
#include <caam_hal_clk.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

void caam_hal_clk_enable(bool enable)
{
	vaddr_t pcc3_base = (vaddr_t)phys_to_virt(PCC3_BASE, MEM_AREA_IO_SEC,
						  PCC3_SIZE);

	if (enable)
		io_setbits32(pcc3_base + PCC_CAAM, PCC_ENABLE_CLOCK);
	else
		io_clrbits32(pcc3_base + PCC_CAAM, PCC_ENABLE_CLOCK);
}
