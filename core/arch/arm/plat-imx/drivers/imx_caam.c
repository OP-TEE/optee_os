// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019 Bryan O'Donoghue
 * Copyright 2019 NXP
 *
 * Bryan O'Donoghue <bryan.odonoghue@linaro.org>
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <imx.h>
#include <imx-regs.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#include "imx_caam.h"

static void caam_enable_clocks(bool enable)
{
	vaddr_t ccm_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	uint32_t reg = 0;
	uint32_t mask = 0;

	reg = io_read32(ccm_base + CCM_CCGR0);

	mask = CCM_CCGR0_CAAM_WRAPPER_IPG  |
		CCM_CCGR0_CAAM_WRAPPER_ACLK |
		CCM_CCGR0_CAAM_SECURE_MEM;

	if (enable)
		reg |= mask;
	else
		reg &= ~mask;

	io_write32((ccm_base + CCM_CCGR0), reg);

	if ((soc_is_imx6dqp() || soc_is_imx6sdl() || soc_is_imx6dq())) {
		/* EMI slow clk */
		reg  = io_read32(ccm_base + CCM_CCGR6);
		mask = CCM_CCGR6_EMI_SLOW;

		if (enable)
			reg |= mask;
		else
			reg &= ~mask;

		io_write32(ccm_base + CCM_CCGR6, reg);
	}

}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CAAM_BASE, CORE_MMU_PGDIR_SIZE);

static TEE_Result init_caam(void)
{
	struct imx_caam_ctrl *caam;
	uint32_t reg;
	int i;

	caam = (struct imx_caam_ctrl *)core_mmu_get_va(CAAM_BASE,
						       MEM_AREA_IO_SEC);
	if (!caam)
		return TEE_ERROR_GENERIC;

	caam_enable_clocks(true);
	/*
	 * Set job-ring ownership to non-secure by default.
	 * A Linux kernel that runs after OP-TEE will run in normal-world
	 * so we want to enable that kernel to have total ownership of the
	 * CAAM job-rings.
	 *
	 * It is possible to use CAAM job-rings inside of OP-TEE i.e. in
	 * secure world code but, to do that OP-TEE and kernel should agree
	 * via a DTB which job-rings are owned by OP-TEE and which are
	 * owned by Kernel, something that the OP-TEE CAAM driver should
	 * set up.
	 *
	 * This code below simply sets a default for the case where no
	 * runtime OP-TEE CAAM code will be run
	 */
	for (i = 0; i < CAAM_NUM_JOB_RINGS; i++) {
		reg = io_read32((vaddr_t)&caam->jr[i].jrmidr_ms);
		reg |= JROWN_NS | JROWN_MID;
		io_write32((vaddr_t)&caam->jr[i].jrmidr_ms, reg);
	}

	return TEE_SUCCESS;
}

driver_init(init_caam);
