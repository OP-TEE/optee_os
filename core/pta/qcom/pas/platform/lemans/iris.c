// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>

#include "iris.h"
#include "pas_iris.h"

#define WRAPPER_SEC_CSR1			0x000b1084
#define WRAPPER_SEC_CSR7			0x000b109c
#define SS_TZ_SEC_THRESHOLD_AV1			0x000c202c

/* AV1 secure session threshold the stock firmware programs on Lemans */
#define IRIS_SEC_AV1_THRESHOLD			1280

/* Written before every release, resume included */
static TEE_Result iris_program_sec_session(vaddr_t base)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	pas_iris_clear_overrides(base);
	io_write32(base + WRAPPER_SEC_CSR1, 1);
	pas_iris_set_thresholds(base);
	io_write32(base + SS_TZ_SEC_THRESHOLD_AV1, IRIS_SEC_AV1_THRESHOLD);
	pas_iris_set_non_vcl_thresholds(base);

	res = pas_iris_write_check(base, SS_TZ_SEC_SID_1_SECURE_OVERRIDE, 1);
	if (res)
		return res;

	res = pas_iris_write_check(base, SS_TZ_SEC_SID_7_SECURE_OVERRIDE, 1);
	if (res)
		return res;

	res = pas_iris_write_check(base, SS_TZ_SEC_SID_F_SECURE_OVERRIDE, 1);
	if (res)
		return res;

	io_write32(base + SS_TZ_SEC_SID_C_SECURE_OVERRIDE, 1);
	io_write32(base + SS_TZ_SEC_SID_D_SECURE_OVERRIDE, 1);
	io_write32(base + SS_TZ_SEC_SID_E_SECURE_OVERRIDE, 1);
	io_write32(base + WRAPPER_SEC_CSR7, 1);

	return TEE_SUCCESS;
}

static TEE_Result iris_release(struct qcom_pas_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = 0;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

	res = iris_program_sec_session(base);
	if (res)
		return res;

	pas_iris_set_cp_layout(base, data->fw_size);
	pas_iris_release_core(base);

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = pas_iris_fill_seed(data);
	if (res)
		return res;

	return iris_release(data);
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!power_on)
		return pas_iris_fw_shutdown(data);

	res = pas_iris_check_fw_size(data);
	if (res)
		return res;

	return iris_release(data);
}

const struct qcom_pas_ops lemans_iris_ops = {
	.fw_init_image = pas_iris_init_image,
	.fw_start = iris_fw_start,
	.fw_shutdown = pas_iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
