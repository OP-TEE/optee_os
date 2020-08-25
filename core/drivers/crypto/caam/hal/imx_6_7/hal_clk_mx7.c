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
	vaddr_t ccm_base = (vaddr_t)phys_to_virt(CCM_BASE, MEM_AREA_IO_SEC, 1);

	if (enable) {
		io_write32(ccm_base + CCM_CCGRx_SET(CCM_CLOCK_DOMAIN_CAAM),
			   CCM_CCGRx_ALWAYS_ON(0));
	} else {
		io_write32(ccm_base + CCM_CCGRx_CLR(CCM_CLOCK_DOMAIN_CAAM),
			   CCM_CCGRx_ALWAYS_ON(0));
	}
}
