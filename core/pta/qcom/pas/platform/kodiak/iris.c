// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <util.h>

#include "iris.h"
#include "pas_iris.h"

#define CPU_CS_VCICMD				0x000a0020
#define CPU_CS_VCICMD_ARP_OFF			BIT(0)
#define SS_TZ_CP_VP8_SECURE_OVERRIDE_DEC	0x000c2098
#define SS_TZ_CP_VP9_SECURE_OVERRIDE_DEC	0x000c209c

/*
 * Written before every release, resume included: VCICMD does not survive
 * an iris power collapse
 */
static TEE_Result iris_program_sec_session(vaddr_t base)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	pas_iris_clear_overrides(base);
	pas_iris_set_thresholds(base);
	pas_iris_set_non_vcl_thresholds(base);
	io_write32(base + SS_TZ_CP_VP8_SECURE_OVERRIDE_DEC, 0);
	io_write32(base + SS_TZ_CP_VP9_SECURE_OVERRIDE_DEC, 0);
	io_write32(base + SS_TZ_SEC_SID_F_SECURE_OVERRIDE, 1);

	res = pas_iris_write_check(base, SS_TZ_SEC_SID_1_SECURE_OVERRIDE, 1);
	if (res)
		return res;

	res = pas_iris_write_check(base, SS_TZ_SEC_SID_7_SECURE_OVERRIDE, 1);
	if (res)
		return res;

	return pas_iris_write_check(base, CPU_CS_VCICMD,
				    CPU_CS_VCICMD_ARP_OFF);
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

const struct qcom_pas_ops kodiak_iris_ops = {
	.fw_init_image = pas_iris_init_image,
	.fw_start = iris_fw_start,
	.fw_shutdown = pas_iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
