// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>

#include "dsp.h"
#include "q6dsp.h"

#define WPSS_QDSP6V67SS_PUB_REG	0x00000000

static const struct dsp_fw_boot_regs wpss_fw_boot_regs = {
	.xo_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x38,
	.sleep_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x3c,
	.core_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x20,
	.rst_evb = WPSS_QDSP6V67SS_PUB_REG + 0x10,
	.core_start = WPSS_QDSP6V67SS_PUB_REG + 0x400,
	.boot_cmd = WPSS_QDSP6V67SS_PUB_REG + 0x404,
	.boot_status = WPSS_QDSP6V67SS_PUB_REG + 0x408,
};

TEE_Result wpss_fw_start(struct qcom_pas_data *data)
{
	return dsp_fw_start(data, &wpss_fw_boot_regs);
}

TEE_Result wpss_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
