// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

register_phys_mem(MEM_AREA_IO_NSEC, TURING_BASE, TURING_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CORE_TOP_CSR_BASE, CORE_TOP_CSR_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, MCU_MCU_CNOC_MASTER_BASE,
		  MCU_MCU_CNOC_MASTER_SIZE);

/* Spark PLL register offsets, relative to the PLL register block base. */
static const struct qcom_pll_offsets spark_pll_offsets = {
	.mode = 0x0,
	.l_val = 0x4,
	.alpha_val = 0x8,
	.alpha_val_u = 0xc,
	.user_ctl = 0x10,
	.user_ctl_u = 0x14,
	.config_ctl = 0x18,
	.test_ctl = 0x1c,
	.test_ctl_u = 0x20,
};

static const struct qcom_pll_config turing_q6_pll_cfg = {
	.offsets = &spark_pll_offsets,
	.l_val = 0x23,
	.cal_l_val = 0x28,
	.alpha_val = 0x0,
	.config_ctl = 0x4001055b,
	.test_ctl = 0x0,
	.test_ctl_u = 0x1,
	.user_ctl = 0x00200007,
	.user_ctl_u = 0x4,
};

static TEE_Result poll_register_clear(vaddr_t reg, uint32_t mask)
{
	uint32_t val = 0;

	if (IO_READ32_POLL_TIMEOUT(reg, val, !(val & mask), 1, 10 * 1000))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

static TEE_Result turing_setup(void)
{
	struct io_pa_va turing_io = { .pa = TURING_BASE };
	vaddr_t turing = io_pa_or_va(&turing_io, TURING_SIZE);
	struct io_pa_va clk_ctl_io = { .pa = GCC_BASE };
	vaddr_t clk_ctl = io_pa_or_va(&clk_ctl_io, GCC_SIZE);

	if (qcom_clock_enable_cbc(clk_ctl + GCC_TURING_CFG_AHB_CBCR) !=
	    TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	if (qcom_clock_enable_cbc(turing + TURING_TURING_WRAPPER_AON_CBCR) !=
	    TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	io_mask32(turing + TURING_AON_CFG_RCGR, 0x0,
		  AON_CFG_RCGR_SRC_SEL_MASK);
	io_setbits32(turing + TURING_AON_CMD_RCGR, AON_CMD_RCGR_UPDATE_BIT);
	if (poll_register_clear(turing + TURING_AON_CMD_RCGR,
				AON_CMD_RCGR_UPDATE_BIT) != TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	if (qcom_clock_enable_cbc(turing + TURING_Q6SS_AHBS_AON_CBCR) !=
	    TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;
	if (qcom_clock_enable_cbc(turing + TURING_Q6SS_AHBM_AON_CBCR) !=
	    TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	/* DDRSS branch and CDSP-debug/AXIM lines are `//`d out in source. */
	io_setbits32(turing + TURING_QDSP6SS_XO_CBCR, XO_CBCR_CLKEN_BIT);
	io_setbits32(turing + TURING_QDSP6SS_SLEEP_CBCR,
		     SLEEP_CBCR_CLKEN_BIT);
	io_setbits32(turing + TURING_QDSP6SS_CORE_CBCR, CORE_CBCR_CLKEN_BIT);
	/* nTURINGQ6DbgVal has no equivalent debug-policy API; always 0. */
	io_write32(turing + TURING_QDSP6SS_DBG_CFG, 0);

	return TEE_SUCCESS;
}

static TEE_Result turing_enable_processor(void)
{
	struct io_pa_va turing_io = { .pa = TURING_BASE };
	vaddr_t turing = io_pa_or_va(&turing_io, TURING_SIZE);
	uint64_t timeout = 0;
	TEE_Result res = TEE_SUCCESS;

	io_write32(turing + TURING_QDSP6SS_RET_CFG, 0);
	io_write32(turing + TURING_QDSP6SS_BOOT_CMD, 1);

	timeout = timeout_init_us(200000 * 5);
	while (!(io_read32(turing + TURING_QDSP6SS_BOOT_STATUS) &
		 BOOT_STATUS_STATUS_BIT)) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
		udelay(5);
	}
	udelay(5);

	res = qcom_spark_pll_enable(turing + TURING_QDSP6SS_PLL_BASE_OFFSET,
				    &turing_q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_set_rate(turing + TURING_QDSP6SS_CORE_CFG_RCGR,
				  turing + TURING_QDSP6SS_CORE_CMD_RCGR,
				  TURING_Q6RCG_CFG_VAL);
	if (res != TEE_SUCCESS)
		return res;

	udelay(5);
	io_setbits32(turing + TURING_QDSP6SS_BOOT_CORE_START,
		     BOOT_CORE_START_START_BIT);

	return TEE_SUCCESS;
}

static TEE_Result turing_reset_processor(void)
{
	struct io_pa_va turing_io = { .pa = TURING_BASE };
	vaddr_t turing = io_pa_or_va(&turing_io, TURING_SIZE);
	struct io_pa_va clk_ctl_io = { .pa = GCC_BASE };
	vaddr_t clk_ctl = io_pa_or_va(&clk_ctl_io, GCC_SIZE);
	struct io_pa_va tcsr_io = { .pa = CORE_TOP_CSR_BASE };
	vaddr_t tcsr = io_pa_or_va(&tcsr_io, CORE_TOP_CSR_SIZE);
	uint64_t timeout = 0;

	io_setbits32(turing + TURING_QDSP6SS_RET_CFG, RET_CFG_RET_ARES_ENA_BIT);

	io_clrbits32(clk_ctl + GCC_TURING_CFG_AHB_CBCR,
		     TURING_CFG_AHB_CBCR_CLK_ENABLE_BIT);

	if (io_read32(tcsr + TCSR_TURING_PWR_ON) & TCSR_TURING_PWR_ON_BIT &&
	    !(io_read32(tcsr + TCSR_TURING_MASTER_IDLE) &
	      TCSR_TURING_MASTER_IDLE_BIT)) {
		io_setbits32(tcsr + TCSR_TURING_HALTREQ,
			     TCSR_TURING_HALTREQ_BIT);

		timeout = timeout_init_us(200000 * 5);
		while (!timeout_elapsed(timeout)) {
			if (io_read32(tcsr + TCSR_TURING_HALTACK) &
			    TCSR_TURING_HALTACK_BIT)
				break;
			udelay(5);
		}
	}

	io_write32(clk_ctl + GCC_COMPUTESS_RESTART, 1);
	udelay(200);

	io_write32(tcsr + TCSR_TURING_HALTREQ, 0);
	udelay(5);

	io_write32(clk_ctl + GCC_COMPUTESS_RESTART, 0);
	udelay(200);

	return TEE_SUCCESS;
}

static TEE_Result lmcu_setup(void)
{
	struct io_pa_va clk_ctl_io = { .pa = GCC_BASE };
	vaddr_t clk_ctl = io_pa_or_va(&clk_ctl_io, GCC_SIZE);

	io_setbits32(clk_ctl + GCC_MCU_AXI_M_CBCR,
		     MCU_AXI_M_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_AHB_CBCR, MCU_AHB_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_SYS_NOC_MCU_AHB_CBCR,
		     SYS_NOC_MCU_AHB_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_F_CBCR, MCU_F_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_PROC_H_CBCR,
		     MCU_PROC_H_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_SS_H_CBCR,
		     MCU_SS_H_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_SS_H_UNCOL_CBCR,
		     MCU_SS_H_UNCOL_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_TMR_CBCR, MCU_TMR_CBCR_CLK_ENABLE_BIT);
	io_setbits32(clk_ctl + GCC_MCU_SLEEP_CBCR,
		     MCU_SLEEP_CBCR_CLK_ENABLE_BIT);

	io_mask32(clk_ctl + GCC_MCU_F_CFG_RCGR,
		  SHIFT_U32(0x1, MCU_F_CFG_RCGR_SRC_SEL_SHIFT),
		  MCU_F_CFG_RCGR_SRC_SEL_MASK);
	io_mask32(clk_ctl + GCC_MCU_F_CFG_RCGR,
		  SHIFT_U32(0x1, MCU_F_CFG_RCGR_SRC_DIV_SHIFT),
		  MCU_F_CFG_RCGR_SRC_DIV_MASK);
	io_setbits32(clk_ctl + GCC_MCU_F_CMD_RCGR, MCU_F_CMD_RCGR_UPDATE_BIT);
	if (poll_register_clear(clk_ctl + GCC_MCU_F_CMD_RCGR,
				MCU_F_CMD_RCGR_UPDATE_BIT) != TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	io_mask32(clk_ctl + GCC_MCU_AHB_CFG_RCGR,
		  SHIFT_U32(0x2, MCU_AHB_CFG_RCGR_SRC_SEL_SHIFT),
		  MCU_AHB_CFG_RCGR_SRC_SEL_MASK);
	io_mask32(clk_ctl + GCC_MCU_AHB_CFG_RCGR,
		  SHIFT_U32(0x2, MCU_AHB_CFG_RCGR_SRC_DIV_SHIFT),
		  MCU_AHB_CFG_RCGR_SRC_DIV_MASK);
	io_setbits32(clk_ctl + GCC_MCU_AHB_CMD_RCGR,
		     MCU_AHB_CMD_RCGR_UPDATE_BIT);
	if (poll_register_clear(clk_ctl + GCC_MCU_AHB_CMD_RCGR,
				MCU_AHB_CMD_RCGR_UPDATE_BIT) != TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

static TEE_Result lmcu_enable_processor(void)
{
	struct io_pa_va clk_ctl_io = { .pa = GCC_BASE };
	vaddr_t clk_ctl = io_pa_or_va(&clk_ctl_io, GCC_SIZE);
	struct io_pa_va mcu_io = { .pa = MCU_MCU_CNOC_MASTER_BASE };
	vaddr_t mcu = io_pa_or_va(&mcu_io, MCU_MCU_CNOC_MASTER_SIZE);

	io_setbits32(clk_ctl + GCC_MCU_PROC_H_CBCR,
		     MCU_PROC_H_CBCR_CLK_ARES_BIT);
	udelay(300);
	io_clrbits32(clk_ctl + GCC_MCU_PROC_H_CBCR,
		     MCU_PROC_H_CBCR_CLK_ARES_BIT);
	io_setbits32(clk_ctl + GCC_MCU_PROC_H_CBCR,
		     MCU_PROC_H_CBCR_CLK_ENABLE_BIT);

	if (poll_register_clear(clk_ctl + GCC_MCU_PROC_H_CBCR,
				MCU_PROC_H_CBCR_CLK_OFF_BIT) != TEE_SUCCESS)
		return TEE_ERROR_TIMEOUT;

	io_setbits32(clk_ctl + GCC_MCU_DBG_CBCR, MCU_DBG_CBCR_CLK_ENABLE_BIT);
	udelay(10);
	io_clrbits32(clk_ctl + GCC_MCU_DBG_CBCR, MCU_DBG_CBCR_CLK_ENABLE_BIT);

	io_write32(mcu + MCU_RVCP_TILE0_BOOT_SUPPRESS, 0);

	return TEE_SUCCESS;
}

static TEE_Result lmcu_reset_processor(void)
{
	struct io_pa_va clk_ctl_io = { .pa = GCC_BASE };
	vaddr_t clk_ctl = io_pa_or_va(&clk_ctl_io, GCC_SIZE);

	io_setbits32(clk_ctl + GCC_MCU_RESTART, MCU_RESTART_SS_RESTART_BIT);
	mdelay(10);
	io_clrbits32(clk_ctl + GCC_MCU_RESTART, MCU_RESTART_SS_RESTART_BIT);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return turing_setup();
	case QCOM_CLKS_LMCU:
		return lmcu_setup();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return turing_enable_processor();
	case QCOM_CLKS_LMCU:
		return lmcu_enable_processor();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return turing_reset_processor();
	case QCOM_CLKS_LMCU:
		return lmcu_reset_processor();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
