// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Clock functions.
 */
#include <caam_hal_clk.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

void caam_hal_clk_enable(bool enable)
{
	vaddr_t pcc2_base = (vaddr_t)phys_to_virt(PCC2_BASE, MEM_AREA_IO_SEC,
						  PCC_CAAM + sizeof(uint32_t));

	if (enable)
		io_write32(pcc2_base + PCC_CAAM, PCC_ENABLE_CLOCK);
	else
		io_write32(pcc2_base + PCC_CAAM, PCC_DISABLE_CLOCK);
}
