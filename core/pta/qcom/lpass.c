// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>

#include "dsp_boot.h"
#include "pas.h"

TEE_Result lpass_fw_start(struct qcom_pas_data *data)
{
	const struct dsp_fw_boot_regs *reg = dsp_fw_get_boot_regs(data->pas_id);
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!reg || !base)
		return TEE_ERROR_GENERIC;

	io_write32(base + reg->lpass.efuse_evb_sel, 0);

	return dsp_fw_start(data, reg);
}

TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
