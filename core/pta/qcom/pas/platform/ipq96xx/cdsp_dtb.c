// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include "cdsp_dtb.h"

/* Pure data image; cdsp_fw_start() reads it via qcom_pas_get_fw(). */
static TEE_Result cdsp_dtb_fw_start(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

/* Shutdown ordering is enforced by pas_platform_shutdown(). */
static TEE_Result cdsp_dtb_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

const struct qcom_pas_ops cdsp_dtb_ops = {
	.fw_start = cdsp_dtb_fw_start,
	.fw_shutdown = cdsp_dtb_fw_shutdown,
};
