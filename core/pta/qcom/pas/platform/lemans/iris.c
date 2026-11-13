// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>

#include "iris.h"
#include "pas_iris.h"

static TEE_Result iris_release(struct qcom_pas_data *data)
{
	vaddr_t base = 0;

	base = io_pa_or_va(&data->base, data->size);
	if (!base)
		return TEE_ERROR_GENERIC;

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
