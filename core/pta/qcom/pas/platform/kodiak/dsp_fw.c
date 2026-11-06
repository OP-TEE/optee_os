// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <pta_qcom_pas.h>
#include <stdint.h>
#include <string.h>

#include "dsp_fw.h"
#include "qdsp6ss.h"

#define CBCR_BRANCH_ENABLE_BIT	BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT	BIT(1)

#define BOOT_CORE_START		BIT(0)
#define BOOT_FSM_TIMEOUT	10000

TEE_Result dsp_fw_start(struct qcom_pas_data *data,
			const struct dsp_fw_start_regs *regs)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!regs)
		return TEE_ERROR_BAD_PARAMETERS;

	io_write32(base + regs->xo_cbcr, CBCR_BRANCH_ENABLE_BIT);
	io_write32(base + regs->sleep_cbcr, CBCR_BRANCH_ENABLE_BIT);

	if (data->pas_id == PAS_ID_TURING)
		io_write32(base + regs->core_cbcr,
			   CBCR_BRANCH_ENABLE_BIT | CBCR_HW_CTL_ENABLE_BIT);
	else
		io_write32(base + regs->core_cbcr, CBCR_BRANCH_ENABLE_BIT);

	io_write32(base + regs->qdsp6ss + QDSP6SS_RST_EVB, data->fw_base >> 4);
	dsb();

	io_write32(base + regs->qdsp6ss + QDSP6SS_BOOT_CORE_START,
		   BOOT_CORE_START);

	return qdsp6ss_boot_fsm(base + regs->qdsp6ss, BOOT_FSM_TIMEOUT);
}

