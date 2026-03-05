// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>

#include "dsp.h"
#include "pas.h"

#define CBCR_BRANCH_ENABLE_BIT	BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT	BIT(1)

#define BOOT_CORE_START		BIT(0)
#define BOOT_CMD_START		BIT(0)
#define BOOT_FSM_TIMEOUT	10000

TEE_Result dsp_fw_start(struct qcom_pas_data *data,
			const struct dsp_fw_boot_regs *regs)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint64_t timeout;

	if (!regs)
		return TEE_ERROR_BAD_PARAMETERS;

	io_write32(base + regs->xo_cbcr, CBCR_BRANCH_ENABLE_BIT);
	io_write32(base + regs->sleep_cbcr, CBCR_BRANCH_ENABLE_BIT);

	if (data->pas_id == PAS_ID_TURING)
		io_write32(base + regs->core_cbcr,
			   CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT);
	else
		io_write32(base + regs->core_cbcr, CBCR_BRANCH_ENABLE_BIT);

	io_write32(base + regs->rst_evb, data->fw_base >> 4);
	dsb();

	io_write32(base + regs->core_start, BOOT_CORE_START);
	io_write32(base + regs->boot_cmd, BOOT_CMD_START);

	timeout = timeout_init_us(BOOT_FSM_TIMEOUT);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(base + regs->boot_status) & BIT(0))
			return TEE_SUCCESS;

		udelay(10);
	}

	EMSG("Timed out waiting for DSP to boot");

	return TEE_ERROR_TIMEOUT;
}

