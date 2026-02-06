// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <kernel/delay.h>

#include "pas.h"

/*QDSP6SS register offsets*/
#define RST_EVB_REG			0x10
#define CORE_START_REG			0x400
#define BOOT_CMD_REG			0x404
#define BOOT_STATUS_REG			0x408
#define RET_CFG_REG			0x1C

#define QDSP6SS_XO_CBCR			0x38
#define QDSP6SS_CORE_CBCR		0x20
#define QDSP6SS_SLEEP_CBCR		0x3c
#define LPASS_BOOT_CORE_START		BIT(0)
#define LPASS_BOOT_CMD_START		BIT(0)
#define LPASS_EFUSE_Q6SS_EVB_SEL	0x0

#define BOOT_FSM_TIMEOUT		10000

TEE_Result wpss_dsp_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, 0x500);
	uint32_t val;
	uint64_t timer;

	/* Enable the XO clock */
	io_write32(base + QDSP6SS_XO_CBCR, 1);

	/* Enable the QDSP6SS sleep clock */
	io_write32(base + QDSP6SS_SLEEP_CBCR, 1);

	/* Enable the QDSP6 core clock */
	io_write32(base + QDSP6SS_CORE_CBCR, 1);

	/* Program boot address */
	io_write32(base + RST_EVB_REG, data->fw_base >> 4);

	/* Flush configuration */
	dsb();

	/* De-assert QDSP6 stop core. QDSP6 will execute after out of reset */
	io_write32(base + CORE_START_REG, LPASS_BOOT_CORE_START);

	/* Trigger boot FSM to start QDSP6 */
	io_write32(base + BOOT_CMD_REG, LPASS_BOOT_CMD_START);

	/* Wait for core to come out of reset */
	timer = timeout_init_us(BOOT_FSM_TIMEOUT);
	do {
		val = io_read32(base + BOOT_STATUS_REG);
		if (val & BIT(0))
			break;
		if (timeout_elapsed(timer))
			break;
		udelay(10);
	} while (1);

	if ((val & BIT(0)) == 0) {
		EMSG("Timed out waiting for DSP to boot :(");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}
