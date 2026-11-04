// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clock_group.h"

#define QCOM_PAS_BOOT_TIMEOUT_US	(200000 * 5)
#define QCOM_PAS_POLL_DELAY_US		5

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CDSP_0_BASE, CDSP_0_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CDSP_1_BASE, CDSP_1_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CDSP_2_BASE, CDSP_2_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CDSP_3_BASE, CDSP_3_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, HPASS_0_BASE, HPASS_0_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, HPASS_1_BASE, HPASS_1_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, HPASS_2_BASE, HPASS_2_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, HPASS_CC_BASE, HPASS_CC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, HPASS_TCM_BASE, HPASS_TCM_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, HPASS_TCSR_BASE, HPASS_TCSR_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, AOSS_CC_BASE, AOSS_CC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, FUSE_CONTROLLER_SW_RANGE4_BASE,
		  FUSE_CONTROLLER_SW_RANGE4_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);

struct cdsp_regs {
	paddr_t base;
	uint32_t tcsr_haltreq;
	uint32_t tcsr_haltack;
	uint32_t tcsr_master_idle;
	uint32_t tcsr_il1_master_idle;
	uint32_t tcsr_pwr_on;
	uint32_t computess_restart_bit;
	uint32_t pdc_sync_reset_off;
};

static const struct cdsp_regs cdsp0_regs = {
	.base = CDSP_0_BASE,
	.tcsr_haltreq = 0x76004,
	.tcsr_haltack = 0x76008,
	.tcsr_master_idle = 0x7600c,
	.tcsr_il1_master_idle = 0x76018,
	.tcsr_pwr_on = 0x76010,
	.computess_restart_bit = BIT(0),
	.pdc_sync_reset_off = RPMH_PDC_COMPUTE_SYNC_RESET,
};

static const struct cdsp_regs cdsp1_regs = {
	.base = CDSP_1_BASE,
	.tcsr_haltreq = 0x76044,
	.tcsr_haltack = 0x76048,
	.tcsr_master_idle = 0x7604c,
	.tcsr_il1_master_idle = 0x76058,
	.tcsr_pwr_on = 0x76050,
	.computess_restart_bit = BIT(1),
	.pdc_sync_reset_off = RPMH_PDC_COMPUTE1_SYNC_RESET,
};

static const struct cdsp_regs cdsp2_regs = {
	.base = CDSP_2_BASE,
	.tcsr_haltreq = 0x7607c,
	.tcsr_haltack = 0x76080,
	.tcsr_master_idle = 0x76084,
	.tcsr_il1_master_idle = 0x76090,
	.tcsr_pwr_on = 0x76088,
	.computess_restart_bit = BIT(2),
	.pdc_sync_reset_off = RPMH_PDC_COMPUTE2_SYNC_RESET,
};

static const struct cdsp_regs cdsp3_regs = {
	.base = CDSP_3_BASE,
	.tcsr_haltreq = 0x760b4,
	.tcsr_haltack = 0x760b8,
	.tcsr_master_idle = 0x760bc,
	.tcsr_il1_master_idle = 0x760c8,
	.tcsr_pwr_on = 0x760c0,
	.computess_restart_bit = BIT(3),
	.pdc_sync_reset_off = RPMH_PDC_COMPUTE3_SYNC_RESET,
};

/* Lucid-OLE uses the same PLL register layout as Lucid-EVO. */
static const struct qcom_pll_offsets lucidole_pll_offsets = {
	.mode = 0x0,
	.opmode = 0x4,
	.l_val = 0x10,
	.alpha_val = 0x14,
	.user_ctl = 0x18,
	.user_ctl_u = 0x1c,
	.config_ctl = 0x20,
	.config_ctl_u = 0x24,
	.config_ctl_u1 = 0x28,
	.test_ctl = 0x2c,
	.test_ctl_u = 0x30,
	.test_ctl_u1 = 0x34,
	.test_ctl_u2 = 0x38,
};

static const struct qcom_pll_config cdsp_q6_pll_cfg = {
	.offsets = &lucidole_pll_offsets,
	.l_val = 0x30,
	.cal_l_val = 0x44,
	.config_ctl = 0x20485699,
	.config_ctl_u = 0x00182261,
	.config_ctl_u1 = 0x82aa299c,
	.user_ctl = 0x00000001,
	.user_ctl_u = 0x00400005,
	.test_ctl = 0x0,
	.test_ctl_u = 0x00000003,
	.test_ctl_u1 = 0x00009000,
	.test_ctl_u2 = 0x00000034,
};

static bool boot_imem_reset_done;

static TEE_Result poll_register_set(vaddr_t reg, uint32_t mask)
{
	uint32_t val = 0;

	if (IO_READ32_POLL_TIMEOUT(reg, val,
				   val & mask, QCOM_PAS_POLL_DELAY_US,
				   QCOM_PAS_BOOT_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

static uint32_t cdsp_efuse_bootimem_ecc_disable_bit(paddr_t base)
{
	switch (base) {
	case CDSP_0_BASE:
		return FEATURE_CONFIG0_CDSP0_BOOTIMEM_ECC_DISABLE_BIT;
	case CDSP_1_BASE:
		return FEATURE_CONFIG0_CDSP1_BOOTIMEM_ECC_DISABLE_BIT;
	case CDSP_2_BASE:
		return FEATURE_CONFIG0_CDSP2_BOOTIMEM_ECC_DISABLE_BIT;
	default:
		return FEATURE_CONFIG0_CDSP3_BOOTIMEM_ECC_DISABLE_BIT;
	}
}

static TEE_Result cdsp_enable_processor(paddr_t base)
{
	struct io_pa_va io = { .pa = base };
	vaddr_t v = io_pa_or_va(&io, CDSP_0_SIZE);
	vaddr_t pub = v + CDSP_QDSP6SS_PUB_OFFSET;
	vaddr_t core_cc = v + CDSP_QDSP6SS_CORE_CC_OFFSET;
	struct io_pa_va fuse_io = { .pa = FUSE_CONTROLLER_SW_RANGE4_BASE };
	vaddr_t fuse = io_pa_or_va(&fuse_io, FUSE_CONTROLLER_SW_RANGE4_SIZE);
	uint64_t timeout = 0;
	TEE_Result res = TEE_SUCCESS;

	/* 1a. Clear RET_CFG; de-assert the ALT ares bypass. */
	io_write32(pub + CDSP_QDSP6SS_RET_CFG, 0);
	io_clrbits32(v + CDSP_CC_ALT_RESET_CTL,
		     CDSP_CC_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);

	/* 2b. De-assert QDSP6 stop-core. */
	io_setbits32(pub + CDSP_QDSP6SS_BOOT_CORE_START,
		     QDSP6SS_BOOT_CORE_START_START_BIT);

	/* 3a. Efuse-gated VTCM ECC disable. */
	if (io_read32(fuse + FEATURE_CONFIG0) &
	    cdsp_efuse_bootimem_ecc_disable_bit(base)) {
		io_clrbits32(pub + CDSP_QDSP6SS_MEMECC_CFG,
			     QDSP6SS_MEMECC_CFG_VTCM_EXT_CTRL_EN_BIT);
		udelay(25);
	}

	/* 4/5. Enable boot FSM auto-break + SW resume, then start the FSM. */
	io_write32(pub + CDSP_QDSP6SS_BOOT_AUTO_BREAK_EN, 1);
	io_write32(pub + CDSP_QDSP6SS_BOOT_CMD, 1);

	/* 6. Wait for the FSM to auto-break. */
	res = poll_register_set(pub + CDSP_QDSP6SS_BOOT_STATUS,
				QDSP6SS_BOOT_STATUS_AUTO_BREAK_BIT);
	if (res != TEE_SUCCESS)
		return res;

	/* Invalidate the ACMU freq word before configuring the Q6 PLL. */
	io_setbits32(core_cc + CDSP_QDSP6SS_CORE_PLL_ACMU,
		     CORE_PLL_ACMU_CMON_FREQ_INVALID_BIT);

	/* 7. Program the Q6 PLL (Lucid-OLE). */
	res = qcom_lucidole_pll_enable(v + CDSP_QDSP6SS_PLL_OFFSET,
				       &cdsp_q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	io_mask32(core_cc + CDSP_QDSP6SS_CORE_PLL_ACMU,
		  cdsp_q6_pll_cfg.l_val * 10,
		  CORE_PLL_ACMU_CMON_FREQ_VAL_MASK);
	io_clrbits32(core_cc + CDSP_QDSP6SS_CORE_PLL_ACMU,
		     CORE_PLL_ACMU_CMON_FREQ_INVALID_BIT);

	/* Program the Q6 core RCG. */
	res = qcom_clock_set_rate(core_cc + CDSP_QDSP6SS_CORE_CFG_RCGR,
				  core_cc + CDSP_QDSP6SS_CORE_CMD_RCGR,
				  CDSP_QDSP0RCG_CFG_VAL);
	if (res != TEE_SUCCESS)
		return res;

	/* 8. Program the Q6 core CBC. */
	io_setbits32(core_cc + CDSP_QDSP6SS_CORE_CBCR,
		     QDSP6SS_CORE_CBCR_CLK_ENABLE_BIT);

	/* 9. Resume the boot FSM. */
	io_write32(pub + CDSP_QDSP6SS_BOOT_RESUME_CMD, 1);

	/* 10. Poll STATUS for boot-FSM completion. */
	timeout = timeout_init_us(200000 * 5);
	while (!timeout_elapsed(timeout)) {
		if (io_read32(pub + CDSP_QDSP6SS_BOOT_STATUS) &
		    QDSP6SS_BOOT_STATUS_STATUS_BIT)
			return TEE_SUCCESS;
		udelay(5);
	}

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result cdsp_reset_processor(const struct cdsp_regs *r)
{
	struct io_pa_va cdsp_io = { .pa = r->base };
	vaddr_t v = io_pa_or_va(&cdsp_io, CDSP_0_SIZE);
	struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
	vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
	struct io_pa_va pdc_io = { .pa = RPMH_PDC_GLOBAL_BASE };
	vaddr_t pdc_global = io_pa_or_va(&pdc_io, RPMH_PDC_GLOBAL_SIZE);
	struct io_pa_va tcsr_io = { .pa = TCSR_MUTEX_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, TCSR_MUTEX_SIZE);
	uint64_t timeout = 0;

	/* Reset the retention logic; assert the ALT ares bypass. */
	io_write32(v + CDSP_QDSP6SS_PUB_OFFSET + CDSP_QDSP6SS_RET_CFG, 0x3);
	io_setbits32(v + CDSP_CC_ALT_RESET_CTL,
		     CDSP_CC_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);

	if ((io_read32(tcsr + r->tcsr_pwr_on) & TCSR_CDSP_BIT) &&
	    ((io_read32(tcsr + r->tcsr_master_idle) & TCSR_CDSP_BIT) == 0 ||
	     (io_read32(tcsr + r->tcsr_il1_master_idle) &
	      TCSR_CDSP_BIT) == 0)) {
		io_setbits32(tcsr + r->tcsr_haltreq, TCSR_CDSP_BIT);

		timeout = timeout_init_us(200000 * 5);
		while (!(io_read32(tcsr + r->tcsr_haltack) & TCSR_CDSP_BIT)) {
			if (timeout_elapsed(timeout))
				break;
			udelay(5);
		}
	}

	/* Force the TBF core clock halt. */
	io_setbits32(v + CDSP_TBF_CFG_OFFSET + CDSP_TBF_CORE_CFG1,
		     TBF_CORE_FORCE_CLK_HALT_BIT);

	/* Assert the Turing PDC reset. */
	io_setbits32(pdc_global + r->pdc_sync_reset_off, PDC_SYNC_RESET_BIT);

	/* 4.2. Trigger the subsystem restart. */
	io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     r->computess_restart_bit);
	udelay(5);
	io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_CONFIG_RESTART,
		     r->computess_restart_bit);
	udelay(200);

	/* Clear the halt request; wait 10ms. */
	io_clrbits32(tcsr + r->tcsr_haltreq, TCSR_CDSP_BIT);
	mdelay(10);

	/* De-assert the PDC reset. */
	io_clrbits32(pdc_global + r->pdc_sync_reset_off, PDC_SYNC_RESET_BIT);

	/* 5. De-assert the subsystem restart. */
	io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     r->computess_restart_bit);
	udelay(5);
	io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_CONFIG_RESTART,
		     r->computess_restart_bit);
	dsb();
	udelay(200);

	return TEE_SUCCESS;
}

static TEE_Result cdsp_setup(paddr_t base)
{
	struct io_pa_va io = { .pa = base };
	vaddr_t v = io_pa_or_va(&io, CDSP_0_SIZE);

	/*
	 * One-time BOOT_IMEM reset workaround, TURING0 only (see the ChipInfo
	 * gap noted in the function header comment for TURING1-3).
	 */
	if (base == CDSP_0_BASE && !boot_imem_reset_done) {
		struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
		vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
		uint32_t dbg_cfg_val = io_read32(v + CDSP_QDSP6SS_PUB_OFFSET +
						  CDSP_QDSP6SS_DBG_CFG);

		io_setbits32(v + CDSP_CC_ALT_RESET_CTL,
			     CDSP_CC_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);
		udelay(50);

		io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
			     COMPUTESS_RESTART_SS_0_BIT);
		udelay(5);
		io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_CONFIG_RESTART,
			     COMPUTESS_RESTART_SS_0_BIT);
		udelay(500);

		io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
			     COMPUTESS_RESTART_SS_0_BIT);
		udelay(5);
		io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_CONFIG_RESTART,
			     COMPUTESS_RESTART_SS_0_BIT);
		udelay(500);

		io_clrbits32(v + CDSP_CC_ALT_RESET_CTL,
			     CDSP_CC_ALT_RESET_CTL_ALT_ARES_BYPASS_BIT);
		udelay(50);

		io_write32(v + CDSP_QDSP6SS_PUB_OFFSET + CDSP_QDSP6SS_DBG_CFG,
			   dbg_cfg_val);

		boot_imem_reset_done = true;
	}

	/* NSP_AUX.GDSCR.HW_CONTROL to HW mode. */
	io_setbits32(v + CDSP_CC_NSPAUX_GDSCR, NSPAUX_GDSCR_HW_CONTROL_BIT);

	if (qcom_clock_enable_cbc(v + CDSP_CC_Q6SS_Q6_AXIM_CBCR) != TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;
	if (qcom_clock_enable_cbc(v + CDSP_CC_Q6SS_AHBM_AON_CBCR) !=
	    TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	/* NSP HSR bus/interface clock branches (plain CLK_ENABLE). */
	io_setbits32(v + CDSP_CC_Q6SS_AXIS_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_NSPAUX_XO_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_CENG_NSP_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_CENG_PROC_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_CENG_AHBS_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_NSPNOC_CFG_AHBS_CBCR,
		     CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_CENG_NOC_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_CENG_NSP_AON_CBCR,
		     CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_NSPNOC_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);

	/* Q6SS slave clock (ENABLE_CBCR_AND_SPIN in the reference). */
	if (qcom_clock_enable_cbc(v + CDSP_CC_Q6SS_AHBS_AON_CBCR) !=
	    TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	io_setbits32(v + CDSP_CC_MCSW_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_MCMW_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_MCSW_AHBS_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);
	io_setbits32(v + CDSP_CC_MCMW_AHBS_CBCR, CDSP_CC_CBCR_CLK_ENABLE_BIT);

	/* Program the debug config register, then a DSB. */
	io_write32(v + CDSP_QDSP6SS_PUB_OFFSET + CDSP_QDSP6SS_DBG_CFG, 0);
	dsb();

	return TEE_SUCCESS;
}

static const struct qcom_pll_config hpass0_q6_pll_cfg = {
	.offsets = &lucidole_pll_offsets,
	.l_val = 0x32,
	.cal_l_val = 0x44,
	.config_ctl = 0x20485699,
	.config_ctl_u = 0x00182261,
	.config_ctl_u1 = 0x82aa299c,
	.user_ctl = 0x00000000,
	.user_ctl_u = 0x00400005,
	.test_ctl = 0x0,
	.test_ctl_u = 0x00000003,
	.test_ctl_u1 = 0x00009000,
	.test_ctl_u2 = 0x00000034,
};

static TEE_Result hpass_enable_processor_0(void)
{
	struct io_pa_va io = { .pa = HPASS_0_BASE };
	vaddr_t v = io_pa_or_va(&io, HPASS_0_SIZE);
	uint64_t timeout = timeout_init_us(200000 * 5);

	io_write32(v + HPASS_QDSP6SS_BOOT_RESUME_CMD, 1);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(v + HPASS_QDSP6SS_BOOT_STATUS) &
		    QDSP6SS_BOOT_STATUS_STATUS_BIT)
			return TEE_SUCCESS;
		udelay(5);
	}

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result hpass_enable_processor_1(void)
{
	struct io_pa_va io = { .pa = HPASS_1_BASE };
	vaddr_t v = io_pa_or_va(&io, HPASS_1_SIZE);

	io_setbits32(v + HPASS_QDSP6SS_BOOT_CORE_START,
		     QDSP6SS_BOOT_CORE_START_START_BIT);
	io_write32(v + HPASS_QDSP6SS_BOOT_CMD, 1);

	return TEE_SUCCESS;
}

static TEE_Result hpass_enable_processor_2(void)
{
	struct io_pa_va io = { .pa = HPASS_2_BASE };
	vaddr_t v = io_pa_or_va(&io, HPASS_2_SIZE);

	io_setbits32(v + HPASS_QDSP6SS_BOOT_CORE_START,
		     QDSP6SS_BOOT_CORE_START_START_BIT);
	io_write32(v + HPASS_QDSP6SS_BOOT_CMD, 1);

	return TEE_SUCCESS;
}

static TEE_Result hpass_noc_quiesce(vaddr_t tcsr, uint32_t qreqn_bit,
				    uint32_t qaccept_bit, uint32_t qdeny_bit)
{
	uint64_t timeout = 0;

	io_clrbits32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QREQN, qreqn_bit);
	timeout = timeout_init_us(500);
	while (io_read32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QACCEPTN) &
	       qaccept_bit) {
		if (timeout_elapsed(timeout))
			goto retry;
		udelay(5);
	}
	return TEE_SUCCESS;

retry:
	if (!(io_read32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QACCEPTN) &
	      qdeny_bit))
		return TEE_SUCCESS;

	io_setbits32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QREQN, qreqn_bit);
	udelay(10);
	io_clrbits32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QREQN, qreqn_bit);

	timeout = timeout_init_us(500);
	while (io_read32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QACCEPTN) &
	       qaccept_bit) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_BUSY;
		udelay(5);
	}

	return TEE_SUCCESS;
}

static TEE_Result hpass_reset_processor(void)
{
	struct io_pa_va cc_io = { .pa = HPASS_CC_BASE };
	vaddr_t cc = io_pa_or_va(&cc_io, HPASS_CC_SIZE);
	struct io_pa_va tcsr_io = { .pa = TCSR_MUTEX_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, TCSR_MUTEX_SIZE);
	struct io_pa_va hpass_tcsr_io = { .pa = HPASS_TCSR_BASE };
	vaddr_t hpass_tcsr = io_pa_or_va(&hpass_tcsr_io, HPASS_TCSR_SIZE);
	struct io_pa_va h0_io = { .pa = HPASS_0_BASE };
	struct io_pa_va h1_io = { .pa = HPASS_1_BASE };
	struct io_pa_va h2_io = { .pa = HPASS_2_BASE };
	vaddr_t h0 = io_pa_or_va(&h0_io, HPASS_0_SIZE);
	vaddr_t h1 = io_pa_or_va(&h1_io, HPASS_1_SIZE);
	vaddr_t h2 = io_pa_or_va(&h2_io, HPASS_2_SIZE);
	struct io_pa_va pdc_io = { .pa = RPMH_PDC_GLOBAL_BASE };
	vaddr_t pdc_global = io_pa_or_va(&pdc_io, RPMH_PDC_GLOBAL_SIZE);
	struct io_pa_va aoss_io = { .pa = AOSS_CC_BASE };
	vaddr_t aoss_cc = io_pa_or_va(&aoss_io, AOSS_CC_SIZE);
	uint64_t timeout = 0;
	uint32_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	io_clrbits32(cc + HPASS_CC_Q6DSPSS0_XO_CBCR,
		     Q6DSPSS_XO_CBCR_IGNORE_ALL_CLK_DIS_BIT);
	io_clrbits32(cc + HPASS_CC_Q6DSPSS1_XO_CBCR,
		     Q6DSPSS_XO_CBCR_IGNORE_ALL_CLK_DIS_BIT);
	io_clrbits32(cc + HPASS_CC_Q6DSPSS2_XO_CBCR,
		     Q6DSPSS_XO_CBCR_IGNORE_ALL_CLK_DIS_BIT);

	io_write32(h0 + HPASS_QDSP6SS_RET_CFG, 0x3);
	io_write32(h1 + HPASS_QDSP6SS_RET_CFG, 0x3);
	io_write32(h2 + HPASS_QDSP6SS_RET_CFG, 0x3);

	for (i = 0; i <= HPASS_ALT_RESET_Q6SS_n_MAXN; i++)
		io_setbits32(hpass_tcsr + HPASS_ALT_RESET_Q6SS_n(i),
			     HPASS_ALT_ARES_ENABLE_BIT);

	/* Isolate each Q6 master bus interface and wait for its halt ACK. */
	io_setbits32(tcsr + TCSR_HPASS_HALTREQ,
		     TCSR_HPASS_Q6SS_0_BUSM_HALTREQ_BIT);
	timeout = timeout_init_us(200000 * 5);
	while (!(io_read32(tcsr + TCSR_HPASS_HALTACK) &
		 TCSR_HPASS_Q6SS_0_BUSM_HALTACK_BIT)) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
		udelay(5);
	}

	io_setbits32(tcsr + TCSR_HPASS_HALTREQ,
		     TCSR_HPASS_Q6SS_1_BUSM_HALTREQ_BIT);
	timeout = timeout_init_us(200000 * 5);
	while (!(io_read32(tcsr + TCSR_HPASS_HALTACK) &
		 TCSR_HPASS_Q6SS_1_BUSM_HALTACK_BIT)) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
		udelay(5);
	}

	io_setbits32(tcsr + TCSR_HPASS_HALTREQ,
		     TCSR_HPASS_Q6SS_2_BUSM_HALTREQ_BIT);
	timeout = timeout_init_us(200000 * 5);
	while (!(io_read32(tcsr + TCSR_HPASS_HALTACK) &
		 TCSR_HPASS_Q6SS_2_BUSM_HALTACK_BIT)) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
		udelay(5);
	}

	/* Clear the HPASS TCSR mutex registers before proceeding. */
	for (i = 0; i <= HPASS_MUTEX_REG_n_MAXN; i++)
		io_write32(hpass_tcsr + HPASS_MUTEX_REG_n(i), 0);

	/* Halt all remaining audio traffic initiators. */
	io_setbits32(tcsr + TCSR_HPASS_HALTREQ, TCSR_HALTREQ_VAL);
	timeout = timeout_init_us(500);
	while ((io_read32(tcsr + TCSR_HPASS_HALTACK) & TCSR_HALTREQ_VAL) !=
	       TCSR_HALTREQ_VAL) {
		if (timeout_elapsed(timeout))
			break;
		udelay(5);
	}

	/*
	 * Halt the Audio NoC channel (Perforce SSR step "6. Halt
	 * AUDIO_NOC").
	 */
	res = hpass_noc_quiesce(tcsr, TCSR_HPASS_AUDIO_NOC_QREQN_BIT,
				TCSR_HPASS_AUDIO_NOC_QACCEPTN_BIT,
				TCSR_HPASS_AUDIO_NOC_QDENY_BIT);
	if (res != TEE_SUCCESS)
		return res;

	/* Halt the ENPU NoC channel (Perforce SSR step "6. Halt ENPU_NOC"). */
	res = hpass_noc_quiesce(tcsr, TCSR_HPASS_ENPU_NOC_QREQN_BIT,
				TCSR_HPASS_ENPU_NOC_QACCEPTN_BIT,
				TCSR_HPASS_ENPU_NOC_QDENY_BIT);
	if (res != TEE_SUCCESS)
		return res;

	/* Halt the AG NoC channel (Perforce SSR step "6. Halt AG_NOC"). */
	res = hpass_noc_quiesce(tcsr, TCSR_HPASS_AG_NOC_QREQN_BIT,
				TCSR_HPASS_AG_NOC_QACCEPTN_BIT,
				TCSR_HPASS_AG_NOC_QDENY_BIT);
	if (res != TEE_SUCCESS)
		return res;

	/* Assert the RPMH PDC audio sync reset and pulse the HPASS restart. */
	io_setbits32(pdc_global + RPMH_PDC_AUDIO_SYNC_RESET,
		     PDC_SYNC_RESET_BIT);
	mdelay(10);
	io_setbits32(aoss_cc + AOSS_CC_HPASS_RESTART,
		     HPASS_RESTART_SS_RESTART_BIT);
	udelay(5);
	io_setbits32(aoss_cc + AOSS_CC_HPASS_CONFIG_RESTART,
		     HPASS_RESTART_SS_RESTART_BIT);
	udelay(200);

	io_clrbits32(pdc_global + RPMH_PDC_AUDIO_SYNC_RESET,
		     PDC_SYNC_RESET_BIT);

	/* Clear all the halt requests, re-open the three NoC channels. */
	io_write32(tcsr + TCSR_HPASS_HALTREQ, 0);
	io_setbits32(tcsr + TCSR_HPASS_AG_NOC_QCHANNEL_QREQN,
		     TCSR_HPASS_AG_NOC_QREQN_BIT |
		     TCSR_HPASS_AUDIO_NOC_QREQN_BIT |
		     TCSR_HPASS_ENPU_NOC_QREQN_BIT);

	io_clrbits32(aoss_cc + AOSS_CC_HPASS_RESTART,
		     HPASS_RESTART_SS_RESTART_BIT);
	udelay(5);
	io_clrbits32(aoss_cc + AOSS_CC_HPASS_CONFIG_RESTART,
		     HPASS_RESTART_SS_RESTART_BIT);
	udelay(100);

	io_write32(h0 + HPASS_QDSP6SS_RET_CFG, 0);
	io_write32(h1 + HPASS_QDSP6SS_RET_CFG, 0);
	io_write32(h2 + HPASS_QDSP6SS_RET_CFG, 0);

	return TEE_SUCCESS;
}

static TEE_Result hpass_setup_0(void)
{
	struct io_pa_va io = { .pa = HPASS_0_BASE };
	vaddr_t v = io_pa_or_va(&io, HPASS_0_SIZE);
	vaddr_t core_cc = v + HPASS_QDSP6SS_CORE_CC_OFFSET;
	struct io_pa_va tcm_io = { .pa = HPASS_TCM_BASE };
	vaddr_t tcm = io_pa_or_va(&tcm_io, HPASS_TCM_SIZE);
	uint64_t timeout = timeout_init_us(200000 * 5);
	uint32_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	io_write32(v + HPASS_QDSP6SS_RET_CFG, 0);
	io_write32(v + HPASS_QDSP6SS_DBG_CFG, 0);

	io_setbits32(v + HPASS_QDSP6SS_BOOT_CORE_START,
		     QDSP6SS_BOOT_CORE_START_START_BIT);
	io_write32(v + HPASS_QDSP6SS_BOOT_AUTO_BREAK_EN, 1);
	io_write32(v + HPASS_QDSP6SS_BOOT_CMD, 1);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(v + HPASS_QDSP6SS_BOOT_STATUS) &
		    QDSP6SS_BOOT_STATUS_AUTO_BREAK_BIT)
			break;
		udelay(5);
	}

	io_setbits32(core_cc + HPASS_QDSP6SS_CORE_CBCR,
		     QDSP6SS_CORE_CBCR_CLK_ENABLE_BIT);

	io_setbits32(core_cc + HPASS_QDSP6SS_CORE_PLL_ACMU,
		     CORE_PLL_ACMU_CMON_FREQ_INVALID_BIT);

	res = qcom_lucidole_pll_enable(v + HPASS_QDSP6SS_PLL_OFFSET,
				       &hpass0_q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	io_mask32(core_cc + HPASS_QDSP6SS_CORE_PLL_ACMU,
		  hpass0_q6_pll_cfg.l_val * 10,
		  CORE_PLL_ACMU_CMON_FREQ_VAL_MASK);
	io_clrbits32(core_cc + HPASS_QDSP6SS_CORE_PLL_ACMU,
		     CORE_PLL_ACMU_CMON_FREQ_INVALID_BIT);

	res = qcom_clock_set_rate(core_cc + HPASS_QDSP6SS_CORE_CFG_RCGR,
				  core_cc + HPASS_QDSP6SS_CORE_CMD_RCGR,
				  CDSP_QDSP0RCG_CFG_VAL);
	if (res != TEE_SUCCESS)
		return res;

	/* Retain the VTCM (HPASS_TCM) memories across CHIP_CX collapse. */
	io_setbits32(tcm + HPASS_TCM_AXIS_HS_CBCR, CBCR_BRANCH_ENABLE_BIT);
	for (i = 0; i <= HPASS_TCM_256KB_BLOCKn_CBCR_MAXN; i++) {
		io_setbits32(tcm + HPASS_TCM_256KB_BLOCKn_CBCR(i),
			     TCM_BLOCK_FORCE_MEM_CORE_ON_BIT);
		io_setbits32(tcm + HPASS_TCM_256KB_BLOCKn_CBCR(i),
			     TCM_BLOCK_CLK_ENABLE_BIT);
	}

	return TEE_SUCCESS;
}

static TEE_Result hpass_setup_1(void)
{
	struct io_pa_va io = { .pa = HPASS_1_BASE };
	vaddr_t v = io_pa_or_va(&io, HPASS_1_SIZE);

	io_write32(v + HPASS_QDSP6SS_RET_CFG, 0);
	io_setbits32(v + HPASS_QDSP6SS_CORE_CC_OFFSET + HPASS_QDSP6SS_CORE_CBCR,
		     QDSP6SS_CORE_CBCR_CLK_ENABLE_BIT);
	io_write32(v + HPASS_QDSP6SS_DBG_CFG, 0);

	return TEE_SUCCESS;
}

static TEE_Result hpass_setup_2(void)
{
	struct io_pa_va io = { .pa = HPASS_2_BASE };
	vaddr_t v = io_pa_or_va(&io, HPASS_2_SIZE);

	io_write32(v + HPASS_QDSP6SS_RET_CFG, 0);
	io_setbits32(v + HPASS_QDSP6SS_CORE_CC_OFFSET + HPASS_QDSP6SS_CORE_CBCR,
		     QDSP6SS_CORE_CBCR_CLK_ENABLE_BIT);
	io_write32(v + HPASS_QDSP6SS_DBG_CFG, 0);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_setup(CDSP_0_BASE);
	case QCOM_CLKS_TURING1:
		return cdsp_setup(CDSP_1_BASE);
	case QCOM_CLKS_TURING2:
		return cdsp_setup(CDSP_2_BASE);
	case QCOM_CLKS_TURING3:
		return cdsp_setup(CDSP_3_BASE);
	case QCOM_CLKS_HPASS0:
		return hpass_setup_0();
	case QCOM_CLKS_HPASS1:
		return hpass_setup_1();
	case QCOM_CLKS_HPASS2:
		return hpass_setup_2();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_enable_processor(CDSP_0_BASE);
	case QCOM_CLKS_TURING1:
		return cdsp_enable_processor(CDSP_1_BASE);
	case QCOM_CLKS_TURING2:
		return cdsp_enable_processor(CDSP_2_BASE);
	case QCOM_CLKS_TURING3:
		return cdsp_enable_processor(CDSP_3_BASE);
	case QCOM_CLKS_HPASS0:
		return hpass_enable_processor_0();
	case QCOM_CLKS_HPASS1:
		return hpass_enable_processor_1();
	case QCOM_CLKS_HPASS2:
		return hpass_enable_processor_2();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_reset_processor(&cdsp0_regs);
	case QCOM_CLKS_TURING1:
		return cdsp_reset_processor(&cdsp1_regs);
	case QCOM_CLKS_TURING2:
		return cdsp_reset_processor(&cdsp2_regs);
	case QCOM_CLKS_TURING3:
		return cdsp_reset_processor(&cdsp3_regs);
	case QCOM_CLKS_HPASS0:
	case QCOM_CLKS_HPASS1:
	case QCOM_CLKS_HPASS2:
		return hpass_reset_processor();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
