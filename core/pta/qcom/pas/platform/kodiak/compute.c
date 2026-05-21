// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>

#include "compute.h"
#include "dsp.h"

#define TURING_QDSP6V68SS_PUB_REG	0x00b00000
#define TURING_QDSP6V68SS_CC_REG	0x00b18000
#define TURING_QDSP6SS_Q6_CC_REG	0x00b40000

static const struct dsp_fw_boot_regs compute_fw_boot_regs = {
	.xo_cbcr = TURING_QDSP6V68SS_CC_REG + 0x54,
	.sleep_cbcr = TURING_QDSP6V68SS_CC_REG + 0x58,
	.core_cbcr = TURING_QDSP6SS_Q6_CC_REG + 0x1040,
	.rst_evb = TURING_QDSP6V68SS_PUB_REG + 0x10,
	.core_start = TURING_QDSP6V68SS_PUB_REG + 0x400,
	.boot_cmd = TURING_QDSP6V68SS_PUB_REG + 0x404,
	.boot_status = TURING_QDSP6V68SS_PUB_REG + 0x408,
};

TEE_Result compute_fw_start(struct qcom_pas_data *data)
{
	return dsp_fw_start(data, &compute_fw_boot_regs);
}

TEE_Result compute_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
