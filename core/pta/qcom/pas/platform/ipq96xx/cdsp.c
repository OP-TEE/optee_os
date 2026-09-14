// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <stddef.h>
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
 * clock-qcom.c registers GCC_BASE MEM_AREA_IO_NSEC; ipq96xx's XPU gates it to
 * secure accesses, and phys_to_virt_io() prefers MEM_AREA_IO_SEC entries.
 */
register_phys_mem(MEM_AREA_IO_SEC, GCC_BASE, GCC_SIZE);

static struct qcom_pas_data *cdsp_dtb_data(void)
{
	struct qcom_pas_subsys *subsys = NULL;
	size_t count = 0;

	subsys = qcom_pas_platform_subsys(&count);
	for (size_t i = 0; i < count; i++)
		if (subsys[i].data.pas_id == PAS_ID_TURING_DTB)
			return &subsys[i].data;

	return NULL;
}

static TEE_Result cdsp_fw_start(struct qcom_pas_data *data)
{
	struct io_pa_va mpm2 = { .pa = MPM2_MPM_BASE };
	struct io_pa_va tcsr_spare = { .pa = TCSR_SPARE_BASE };
	struct qcom_pas_data *dtb = cdsp_dtb_data();
	vaddr_t turing = io_pa_or_va(&data->base, data->size);
	vaddr_t tcsr = 0;
	vaddr_t qdsp6ss = 0;
	vaddr_t mpm2_va = 0;
	vaddr_t spare_va = 0;
	uint32_t boot_status = 0;
	uint32_t boot_vector_evb = 0;
	uint64_t timeout = 0;
	int debug_q6 = 0;

	if (!turing || !dtb)
		return TEE_ERROR_BAD_STATE;
	if (!dtb->fw_base || !dtb->fw_size)
		return TEE_ERROR_NO_DATA;

	tcsr = turing + TURING_TCSR_OFFSET;
	qdsp6ss = turing + TURING_QDSP6SS_OFFSET;

	mpm2_va = io_pa_or_va(&mpm2, MPM2_MPM_SIZE);
	spare_va = io_pa_or_va(&tcsr_spare, TCSR_SPARE_SIZE);
	if (!mpm2_va || !spare_va)
		return TEE_ERROR_GENERIC;

	boot_vector_evb = (uint32_t)(data->fw_base >> 4);
	debug_q6 = io_read32(spare_va) & 0x1;

	io_write32(tcsr + TURING_TCSR_RST_EVB_SEL_REG, RST_EVB_SEL_ENABLE);
	io_write32(tcsr + TURING_TCSR_RST_EVB_ADDR_REG, boot_vector_evb);

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

	io_write32(qdsp6ss + Q6SS_BOOT_CMD_REG, BOOT_CMD_START);

	dsb();
	isb();

	timeout = timeout_init_us(BOOT_TIMEOUT_MS * 1000);
	do {
		boot_status = io_read32(qdsp6ss + Q6SS_BOOT_STATUS_REG);
		if (boot_status == Q6SS_BOOT_STATUS_STAGE1)
			break;
		udelay(10);
	} while (!timeout_elapsed(timeout));

	if (boot_status != Q6SS_BOOT_STATUS_STAGE1) {
		EMSG("CDSP stage 1 boot timeout - status: %#"PRIx32,
		     boot_status);
		return TEE_ERROR_TIMEOUT;
	}

	io_write32(mpm2_va + MPM2_MPM_CONTROL_CNTCR, BIT(0));
	io_write32(qdsp6ss + Q6SS_BOOT_RESUME_CMD_REG, BIT(0));

	timeout = timeout_init_us(BOOT_TIMEOUT_MS * 1000);
	do {
		boot_status = io_read32(qdsp6ss + Q6SS_BOOT_STATUS_REG);
		if (boot_status == Q6SS_BOOT_STATUS_STAGE2)
			break;
		udelay(10);
	} while (!timeout_elapsed(timeout));

	if (boot_status != Q6SS_BOOT_STATUS_STAGE2) {
		EMSG("CDSP stage 2 boot timeout - status: %#"PRIx32,
		     boot_status);
		return TEE_ERROR_TIMEOUT;
	}

	DMSG("CDSP boot completed successfully");
	dsb();

	return TEE_SUCCESS;
}

enum cdsp_state {
	CDSP_POWERED,	/* subsystem is powered on */
	CDSP_HALTED,	/* masters halted (halt acknowledged) */
	CDSP_RUNNING,	/* halt request released */
	CDSP_IDLE,	/* masters idle after reset */
};

/* Drive the register write that requests a transition into @state. */
static void cdsp_state_enter(vaddr_t tcsr, enum cdsp_state state)
{
	switch (state) {
	case CDSP_HALTED:
		io_write32(tcsr + TCSR_TURING_HALTREQ, 0x1);
		break;
	case CDSP_RUNNING:
		io_write32(tcsr + TCSR_TURING_HALTREQ, 0x0);
		break;
	default:
		break;
	}
}

/* Both Turing master ports report idle after a reset. */
static bool cdsp_masters_idle(vaddr_t tcsr)
{
	return (io_read32(tcsr + TCSR_TURING_MASTER_IDLE) & 0x1) &&
	       (io_read32(tcsr + TCSR_TURING_IL1_MASTER_IDLE) & 0x1);
}

/* Poll until @state is observed; return false on timeout. */
static bool cdsp_state_sync(vaddr_t tcsr, enum cdsp_state state)
{
	uint32_t poll_ms = (state == CDSP_POWERED) ? 1000 : 5000;
	uint64_t timeout = timeout_init_us(poll_ms * 1000);

	do {
		switch (state) {
		case CDSP_POWERED:
			if (io_read32(tcsr + TCSR_TURING_PWR_ON) & 0x1)
				return true;
			break;
		case CDSP_HALTED:
			if (io_read32(tcsr + TCSR_TURING_HALTACK) & 0x1)
				return true;
			break;
		case CDSP_IDLE:
			if (cdsp_masters_idle(tcsr))
				return true;
			break;
		default:
			return false;
		}
		udelay(10);
	} while (!timeout_elapsed(timeout));

	return false;
}

static TEE_Result cdsp_fw_shutdown(struct qcom_pas_data *data)
{
	struct io_pa_va gcc = { .pa = GCC_BASE };
	struct io_pa_va cdsp_tcsr = { .pa = CDSP_TCSR_BASE };
	vaddr_t turing = data->base.va;
	vaddr_t turing_cc = 0;
	vaddr_t gcc_va = 0;
	vaddr_t tcsr = 0;
	uint32_t val = 0;
	bool idle = false;

	if (!turing)
		return TEE_ERROR_BAD_STATE;

	turing_cc = turing + TURING_CC_OFFSET;

	gcc_va = io_pa_or_va(&gcc, GCC_SIZE);
	tcsr = io_pa_or_va(&cdsp_tcsr, CDSP_TCSR_SIZE);
	if (!gcc_va || !tcsr)
		return TEE_ERROR_GENERIC;

	if (cdsp_state_sync(tcsr, CDSP_POWERED)) {
		cdsp_state_enter(tcsr, CDSP_HALTED);
		if (!cdsp_state_sync(tcsr, CDSP_HALTED)) {
			EMSG("Failed to receive halt acknowledgment");
			return TEE_ERROR_TIMEOUT;
		}
	} else {
		DMSG("CDSP already powered off, skipping halt request");
	}

	io_write32(turing_cc + TURING_CC_ALT_RESET_CTL, 0x1);

	/* Disable the AHBS clock across the reset. */
	io_write32(gcc_va + GCC_TURING_AHBS_CLK_CBCR, 0);

	val = io_read32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART);
	io_write32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART, val | 0x1);
	io_write32(gcc_va + GCC_TURINGSS_BCR, 0x1);
	mdelay(1000);

	cdsp_state_enter(tcsr, CDSP_RUNNING);
	io_write32(gcc_va + GCC_TURINGSS_BCR, 0x0);
	val = io_read32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART);
	io_write32(gcc_va + GCC_RST_CTL_COMPUTESS_RESTART, val & ~0x1);

	mdelay(1000);
	idle = cdsp_state_sync(tcsr, CDSP_IDLE);
	if (!idle)
		EMSG("CDSP failed to reach idle state after reset");

	io_write32(gcc_va + GCC_TURING_AHBS_CLK_CBCR, BIT(0));
	io_write32(turing_cc + TURING_CC_ALT_RESET_CTL, 0x0);

	if (!idle)
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

static TEE_Result cdsp_dtb_fw_start(struct qcom_pas_data *data __unused)
{
	/* The blob carries no processor; cdsp_fw_start() consumes it. */
	return TEE_SUCCESS;
}

static TEE_Result cdsp_dtb_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

const struct qcom_pas_ops cdsp_ops = {
	.fw_start = cdsp_fw_start,
	.fw_shutdown = cdsp_fw_shutdown,
};

const struct qcom_pas_ops cdsp_dtb_ops = {
	.fw_start = cdsp_dtb_fw_start,
	.fw_shutdown = cdsp_dtb_fw_shutdown,
};
