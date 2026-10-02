// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>

#include "gpu.h"

/* Relative to GPU_BASE */
#define GPU_CP_SECVID_UCODE_TRUSTED_BASE_LO	0x3c000
#define GPU_CP_SECVID_UCODE_TRUSTED_BASE_HI	0x3c004
#define GPU_CP_SECVID_CP_TRUST_CONFIGURE	0x3c008

#define CP_TRUST_CONFIGURE_VALUE		0x3

/*
 * Point the CP at the loaded zap shader as its trusted microcode. The
 * registers lose their contents when the GPU powers down, so a resume
 * programs them again.
 */
static TEE_Result gpu_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return TEE_ERROR_GENERIC;

	if (!data->fw_base)
		return TEE_ERROR_NO_DATA;

	io_write32(base + GPU_CP_SECVID_UCODE_TRUSTED_BASE_LO,
		   (uint32_t)data->fw_base);
	io_write32(base + GPU_CP_SECVID_UCODE_TRUSTED_BASE_HI,
		   (uint32_t)(data->fw_base >> 32));
	io_write32(base + GPU_CP_SECVID_CP_TRUST_CONFIGURE,
		   CP_TRUST_CONFIGURE_VALUE);

	return TEE_SUCCESS;
}

static TEE_Result gpu_fw_set_state(struct qcom_pas_data *data,
				   bool on __unused)
{
	return gpu_fw_start(data);
}

static TEE_Result gpu_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

const struct qcom_pas_ops gpu_ops = {
	.fw_start = gpu_fw_start,
	.fw_shutdown = gpu_fw_shutdown,
	.fw_set_state = gpu_fw_set_state,
};
