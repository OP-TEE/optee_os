// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include "cdsp.h"
#include "pas_subsys.h"

/* Sub-block offsets within the TURING window. */
#define TURING_CC_OFFSET		0x00008000
#define TURING_TCSR_OFFSET		0x00080000
#define TURING_QDSP6SS_OFFSET		0x00300000

/* QDSP6 boot registers. */
#define Q6SS_BOOT_CORE_START_REG	0x400
#define Q6SS_BOOT_CMD_REG		0x404
#define Q6SS_BOOT_STATUS_REG		0x408
#define Q6SS_BOOT_AUTO_BREAK_EN_REG	0x410
#define Q6SS_BOOT_RESUME_CMD_REG	0x414

/* Turing TCSR reset-vector registers. */
#define TURING_TCSR_RST_EVB_SEL_REG	0x1000
#define TURING_TCSR_RST_EVB_ADDR_REG	0x1004

/* Turing CC alternate-reset control. */
#define TURING_CC_ALT_RESET_CTL		0x10034

/* CDSP TCSR control registers. */
#define TCSR_TURING_HALTREQ		0x0000
#define TCSR_TURING_HALTACK		0x0004
#define TCSR_TURING_MASTER_IDLE		0x0008
#define TCSR_TURING_PWR_ON		0x000c
#define TCSR_TURING_IL1_MASTER_IDLE	0x0010

/* MPM2 control register. */
#define MPM2_MPM_CONTROL_CNTCR		0x1000

/* GCC reset and clock control registers. */
#define GCC_RST_CTL_COMPUTESS_RESTART	0x47020
#define GCC_TURINGSS_BCR		0x18000
#define GCC_TURING_AHBS_CLK_CBCR	0x18038

/* Boot control and DTB configuration registers. */
#define Q6SS_BOOT_CTRL_REG		0x18
#define DTB_CONFIG_0_REG		0x60
#define DTB_CONFIG_1_REG		0x64
#define DTB_CONFIG_2_REG		0x68
#define DTB_CONFIG_3_REG		0x6c
#define DTB_CONFIG_5_REG		0x74

/* Two-stage boot FSM status values. */
#define Q6SS_BOOT_STATUS_STAGE1		0x80000000
#define Q6SS_BOOT_STATUS_STAGE2		0x1

/* Boot control values. */
#define BOOT_CORE_START_ENABLE		0x1
#define BOOT_AUTO_BREAK_ENABLE		0x1
#define BOOT_CMD_START			0x1
#define RST_EVB_SEL_ENABLE		0x1
#define Q6SS_BREAK_AT_START		0x20000001

/* DTB configuration values. */
#define DTB_CHIP_FAMILY_ID		0x00b40303
#define DTB_VERSION			0x00000100

#define BOOT_TIMEOUT_MS			1000
#define CLOCK_DELAY_MS			10

register_phys_mem(MEM_AREA_IO_SEC, MPM2_MPM_BASE, MPM2_MPM_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, TCSR_SPARE_BASE, TCSR_SPARE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, CDSP_TCSR_BASE, CDSP_TCSR_SIZE);

/*
 * clk.c registers GCC_BASE MEM_AREA_IO_NSEC; ipq96xx's XPU gates it to
 * secure accesses, and phys_to_virt_io() prefers MEM_AREA_IO_SEC entries.
 */
register_phys_mem(MEM_AREA_IO_SEC, GCC_BASE, GCC_SIZE);

static bool cdsp_boot_stage1_done(uint32_t val)
{
	return val == Q6SS_BOOT_STATUS_STAGE1;
}

static bool cdsp_boot_stage2_done(uint32_t val)
{
	return val == Q6SS_BOOT_STATUS_STAGE2;
}

static bool cdsp_bit0_set(uint32_t val)
{
	return val & 0x1;
}

static TEE_Result cdsp_fw_start(struct qcom_pas_data *data)
{
	struct io_pa_va tcsr_spare = { .pa = TCSR_SPARE_BASE };
	vaddr_t turing = io_pa_or_va(&data->base, data->size);
	struct io_pa_va mpm2 = { .pa = MPM2_MPM_BASE };
	struct qcom_pas_subsys *dtb_subsys = NULL;
	struct qcom_pas_data *dtb = NULL;
	vaddr_t spare_va = 0;
	vaddr_t qdsp6ss = 0;
	vaddr_t mpm2_va = 0;
	int debug_q6 = 0;
	vaddr_t tcsr = 0;
	int res = 0;

	if (!turing)
		return TEE_ERROR_BAD_STATE;

	dtb_subsys = qcom_pas_lookup(data->dtb_pas_id);
	if (!dtb_subsys || !qcom_pas_is_loaded(data->dtb_pas_id)) {
		EMSG("CDSP DTB firmware not loaded");
		return TEE_ERROR_BAD_STATE;
	}
	dtb = &dtb_subsys->data;

	tcsr = turing + TURING_TCSR_OFFSET;
	qdsp6ss = turing + TURING_QDSP6SS_OFFSET;

	mpm2_va = io_pa_or_va(&mpm2, MPM2_MPM_SIZE);
	spare_va = io_pa_or_va(&tcsr_spare, TCSR_SPARE_SIZE);
	if (!mpm2_va || !spare_va)
		return TEE_ERROR_GENERIC;

	debug_q6 = io_read32(spare_va) & 0x1;

	io_write32(tcsr + TURING_TCSR_RST_EVB_SEL_REG, RST_EVB_SEL_ENABLE);
	io_write32(tcsr + TURING_TCSR_RST_EVB_ADDR_REG, data->fw_base >> 4);

	io_write32(qdsp6ss + Q6SS_BOOT_CORE_START_REG, BOOT_CORE_START_ENABLE);
	io_write32(qdsp6ss + Q6SS_BOOT_AUTO_BREAK_EN_REG,
		   BOOT_AUTO_BREAK_ENABLE);

	io_write32(qdsp6ss + DTB_CONFIG_0_REG, (uint32_t)dtb->fw_base);
	io_write32(qdsp6ss + DTB_CONFIG_1_REG, (uint32_t)(dtb->fw_base >> 32));
	io_write32(qdsp6ss + DTB_CONFIG_2_REG, DTB_CHIP_FAMILY_ID);
	io_write32(qdsp6ss + DTB_CONFIG_3_REG, DTB_VERSION);
	io_write32(qdsp6ss + DTB_CONFIG_5_REG, (uint32_t)dtb->fw_size);
	if (debug_q6)
		io_write32(qdsp6ss + Q6SS_BOOT_CTRL_REG, Q6SS_BREAK_AT_START);

	/* Stage 1: kick off the boot FSM and wait for the initial halt. */
	io_write32(qdsp6ss + Q6SS_BOOT_CMD_REG, BOOT_CMD_START);

	dsb();
	isb();

	REG_POLL_TIMEOUT(qdsp6ss + Q6SS_BOOT_STATUS_REG, BOOT_TIMEOUT_MS * 1000,
			 10, &res, cdsp_boot_stage1_done);
	if (res) {
		EMSG("CDSP stage 1 boot timeout - status: %#"PRIx32,
		     io_read32(qdsp6ss + Q6SS_BOOT_STATUS_REG));
		return TEE_ERROR_TIMEOUT;
	}

	/* Stage 2: resume out of the stage-1 breakpoint. */
	io_write32(mpm2_va + MPM2_MPM_CONTROL_CNTCR, BIT(0));
	io_write32(qdsp6ss + Q6SS_BOOT_RESUME_CMD_REG, BIT(0));

	REG_POLL_TIMEOUT(qdsp6ss + Q6SS_BOOT_STATUS_REG, BOOT_TIMEOUT_MS * 1000,
			 10, &res, cdsp_boot_stage2_done);
	if (res) {
		EMSG("CDSP stage 2 boot timeout - status: %#"PRIx32,
		     io_read32(qdsp6ss + Q6SS_BOOT_STATUS_REG));
		return TEE_ERROR_TIMEOUT;
	}

	DMSG("CDSP boot completed successfully");
	dsb();

	return TEE_SUCCESS;
}

static void cdsp_halt_axi_port(vaddr_t tcsr, bool halt_en)
{
	io_write32(tcsr + TCSR_TURING_HALTREQ, halt_en ? 0x1 : 0x0);
}

/* Both Turing master ports must report idle after a reset. */
static bool cdsp_wait_masters_idle(vaddr_t tcsr)
{
	uint64_t timeout = timeout_init_us(5000 * 1000);
	bool idle = false;

	idle = (io_read32(tcsr + TCSR_TURING_MASTER_IDLE) & 0x1) &&
	       (io_read32(tcsr + TCSR_TURING_IL1_MASTER_IDLE) & 0x1);
	while (!idle) {
		if (timeout_elapsed(timeout))
			return false;
		udelay(10);
		idle = (io_read32(tcsr + TCSR_TURING_MASTER_IDLE) & 0x1) &&
		       (io_read32(tcsr + TCSR_TURING_IL1_MASTER_IDLE) & 0x1);
	}

	return true;
}

static TEE_Result cdsp_fw_shutdown(struct qcom_pas_data *data)
{
	struct io_pa_va cdsp_tcsr = { .pa = CDSP_TCSR_BASE };
	struct io_pa_va gcc = { .pa = GCC_BASE };
	vaddr_t turing = data->base.va;
	vaddr_t turing_cc = 0;
	vaddr_t gcc_va = 0;
	bool idle = false;
	vaddr_t tcsr = 0;
	uint32_t val = 0;
	int res = 0;

	if (!turing)
		return TEE_ERROR_BAD_STATE;

	turing_cc = turing + TURING_CC_OFFSET;

	gcc_va = io_pa_or_va(&gcc, GCC_SIZE);
	tcsr = io_pa_or_va(&cdsp_tcsr, CDSP_TCSR_SIZE);
	if (!gcc_va || !tcsr)
		return TEE_ERROR_GENERIC;

	/* Halt the AXI ports, but only if the core is actually powered. */
	REG_POLL_TIMEOUT(tcsr + TCSR_TURING_PWR_ON, 1000 * 1000, 10, &res,
			 cdsp_bit0_set);
	if (!res) {
		cdsp_halt_axi_port(tcsr, true);
		REG_POLL_TIMEOUT(tcsr + TCSR_TURING_HALTACK, 5000 * 1000, 10,
				 &res, cdsp_bit0_set);
		if (res) {
			EMSG("Failed to receive halt acknowledgment");
			return TEE_ERROR_TIMEOUT;
		}
	} else {
		DMSG("CDSP already powered off, skipping halt request");
	}

	/* Assert the block reset while gating the AHBS clock across it. */
	io_write32(turing_cc + TURING_CC_ALT_RESET_CTL, 0x1);
	io_write32(gcc_va + GCC_TURING_AHBS_CLK_CBCR, 0);

	val = io_read32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART);
	io_write32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART, val | 0x1);
	io_write32(gcc_va + GCC_TURINGSS_BCR, 0x1);
	mdelay(1000);

	/* Release the reset and the AXI halt. */
	cdsp_halt_axi_port(tcsr, false);
	io_write32(gcc_va + GCC_TURINGSS_BCR, 0x0);
	val = io_read32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART);
	io_write32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART, val & ~0x1);

	mdelay(1000);

	/* Confirm the core went idle, then restore the AHBS clock. */
	idle = cdsp_wait_masters_idle(tcsr);

	io_write32(gcc_va + GCC_TURING_AHBS_CLK_CBCR, BIT(0));
	io_write32(turing_cc + TURING_CC_ALT_RESET_CTL, 0x0);

	if (!idle) {
		EMSG("CDSP failed to reach idle state after reset");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}

const struct qcom_pas_ops cdsp_ops = {
	.fw_start = cdsp_fw_start,
	.fw_shutdown = cdsp_fw_shutdown,
};
