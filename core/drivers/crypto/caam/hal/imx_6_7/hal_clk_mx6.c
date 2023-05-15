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
	vaddr_t ccm_base = (vaddr_t)phys_to_virt(CCM_BASE, MEM_AREA_IO_SEC,
						 CCM_SIZE);
	uint32_t reg = 0;
	uint32_t mask = 0;

	reg = io_read32(ccm_base + CCM_CCGR0);

	mask = BM_CCM_CCGR0_CAAM_WRAPPER_IPG | BM_CCM_CCGR0_CAAM_WRAPPER_ACLK |
	       BM_CCM_CCGR0_CAAM_SECURE_MEM;

	if (enable)
		reg |= mask;
	else
		reg &= ~mask;

	io_write32(ccm_base + CCM_CCGR0, reg);

	if (!soc_is_imx6ul()) {
		/* EMI slow clk */
		reg = io_read32(ccm_base + CCM_CCGR6);
		mask = BM_CCM_CCGR6_EMI_SLOW;

		if (enable)
			reg |= mask;
		else
			reg &= ~mask;

		io_write32(ccm_base + CCM_CCGR6, reg);
	}
}
