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
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/cache.h>

#include "imx_caam.h"

static uint8_t stored_key[MKVB_SIZE] = { 0 };
static bool mkvb_retrieved;

static void caam_enable_clocks(void)
{
	vaddr_t ccm_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	uint32_t reg = 0;
	uint32_t mask = 0;

	reg = io_read32(ccm_base + CCM_CCGR0);

	mask = CCM_CCGR0_CAAM_WRAPPER_IPG  |
		CCM_CCGR0_CAAM_WRAPPER_ACLK |
		CCM_CCGR0_CAAM_SECURE_MEM;

	reg |= mask;

	io_write32(ccm_base + CCM_CCGR0, reg);

	if (soc_is_imx6dqp() || soc_is_imx6sdl() || soc_is_imx6dq()) {
		/* EMI slow clk */
		reg  = io_read32(ccm_base + CCM_CCGR6);
		mask = CCM_CCGR6_EMI_SLOW;

		reg |= mask;

		io_write32(ccm_base + CCM_CCGR6, reg);
	}
}

static TEE_Result imx_caam_reset_jr(struct imx_caam_ctrl *ctrl)
{
	uint32_t reg_val = 0;
	uint32_t timeout = 1000;

	io_write32((vaddr_t)&ctrl->jrcfg[MKVB_JR].jrcr, 1);
	do {
		reg_val = io_read32((vaddr_t)&ctrl->jrcfg[MKVB_JR].jrintr);
		reg_val &= 0xc;
	} while ((reg_val == 0x4) && --timeout);

	if (!timeout)
		return TEE_ERROR_SECURITY;

	io_write32((vaddr_t)&ctrl->jrcfg[MKVB_JR].jrcr, 1);
	do {
		reg_val = io_read32((vaddr_t)&ctrl->jrcfg[MKVB_JR].jrintr);
		reg_val &= 0xc;
	} while ((reg_val & 0x1) && --timeout);

	if (!timeout)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

static TEE_Result mkvb_init_jr(struct imx_mkvb *mkvb)
{
	struct imx_caam_ctrl *ctrl = mkvb->ctrl;
	TEE_Result ret;

	ret = imx_caam_reset_jr(ctrl);
	if (ret)
		return ret;

	mkvb->njobs = 4;
	io_write32((vaddr_t)&ctrl->jrstartr, MKVB_JR1_START);
	io_write32((vaddr_t)&ctrl->jrcfg[MKVB_JR].irbar_ls,
		   virt_to_phys(&mkvb->jr.inring));
	io_write32((vaddr_t)&ctrl->jrcfg[MKVB_JR].irsr, mkvb->njobs);
	io_write32((vaddr_t)&ctrl->jrcfg[MKVB_JR].orbar_ls,
		   virt_to_phys(&mkvb->jr.outring));
	io_write32((vaddr_t)&ctrl->jrcfg[MKVB_JR].orsr, mkvb->njobs);

	return TEE_SUCCESS;
}

static TEE_Result caam_get_mkvb(uint8_t *dest)
{
	struct imx_mkvb mkvb = { 0 };
	TEE_Result ret = TEE_ERROR_SECURITY;
	paddr_t desc_paddr = 0;
	int counter = 0;

	mkvb.ctrl = (struct imx_caam_ctrl *)
		core_mmu_get_va(CAAM_BASE, MEM_AREA_IO_SEC);

	ret = mkvb_init_jr(&mkvb);
	if (ret)
		goto out;

	mkvb.descriptor[0] = MKVB_DESC_HEADER;
	mkvb.descriptor[1] = MKVB_DESC_SEQ_OUT;
	mkvb.descriptor[2] = virt_to_phys(&mkvb.outbuf);
	cache_operation(TEE_CACHEFLUSH, &mkvb.outbuf, MKVB_SIZE);
	mkvb.descriptor[3] = MKVB_DESC_BLOB;
	cache_operation(TEE_CACHEFLUSH, &mkvb.descriptor,
			sizeof(mkvb.descriptor));

	desc_paddr = virt_to_phys(&mkvb.descriptor);
	memcpy(&mkvb.jr.inring, &desc_paddr, sizeof(desc_paddr));
	cache_operation(TEE_CACHEFLUSH, &mkvb.jr,
			sizeof(mkvb.jr.inring[0]));

	/* Tell CAAM that one job is available */
	io_write32((vaddr_t)&mkvb.ctrl->jrcfg[MKVB_JR].irjar, 1);

	/* Busy loop until job is completed */
	while (io_read32((vaddr_t)&mkvb.ctrl->jrcfg[MKVB_JR].orsfr) != 1) {
		counter++;
		if (counter > 10000)
			goto out;
	}

	cache_operation(TEE_CACHEINVALIDATE, &mkvb.jr, sizeof(mkvb.jr));
	cache_operation(TEE_CACHEINVALIDATE, &mkvb.outbuf, MKVB_SIZE);
	DHEXDUMP(&mkvb.outbuf, MKVB_SIZE);

	if (mkvb.jr.outring[0].status != 0)
		goto out;

	memcpy(dest, &mkvb.outbuf, MKVB_SIZE);
	ret = TEE_SUCCESS;
out:
	io_write32((vaddr_t)&mkvb.ctrl->scfgr, PRIBLOB_11);
	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	int ret = TEE_ERROR_SECURITY;

	if (!mkvb_retrieved) {
		ret = caam_get_mkvb(stored_key);
		if (ret)
			return ret;
		mkvb_retrieved = true;
	}
	memcpy(&hwkey->data, &stored_key, sizeof(hwkey->data));
	return TEE_SUCCESS;
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

	caam_enable_clocks();
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
