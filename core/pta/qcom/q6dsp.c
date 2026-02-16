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

#include "dsp_boot.h"
#include "pas.h"

TEE_Result wpss_fw_start(struct qcom_pas_data *data)
{
	return dsp_fw_start(data, dsp_fw_get_boot_regs(data->pas_id));
}

TEE_Result wpss_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
