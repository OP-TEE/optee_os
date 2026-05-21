// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>

#include "dsp.h"
#include "lpass.h"

#define LPASS_QDSP6V67SS_PUB_REG	0x00400000
#define LPASS_MCC_REG			0x00950000

static const struct dsp_fw_boot_regs lpass_fw_boot_regs = {
	.xo_cbcr = LPASS_QDSP6V67SS_PUB_REG + 0x38,
	.sleep_cbcr = LPASS_QDSP6V67SS_PUB_REG + 0x3c,
	.core_cbcr = LPASS_QDSP6V67SS_PUB_REG + 0x20,
	.rst_evb = LPASS_QDSP6V67SS_PUB_REG + 0x10,
	.core_start = LPASS_QDSP6V67SS_PUB_REG + 0x400,
	.boot_cmd = LPASS_QDSP6V67SS_PUB_REG + 0x404,
	.boot_status = LPASS_QDSP6V67SS_PUB_REG + 0x408,
	.lpass.efuse_evb_sel = LPASS_MCC_REG + 0xb000,
};

TEE_Result lpass_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return TEE_ERROR_GENERIC;

	io_write32(base + lpass_fw_boot_regs.lpass.efuse_evb_sel, 0);

	return dsp_fw_start(data, &lpass_fw_boot_regs);
}

TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
