// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include "cdsp_dtb.h"

/*
 * The DTB blob carries no processor of its own: it is a data image that
 * cdsp_fw_start() (see cdsp.c) reads once it observes this subsystem is
 * loaded, via qcom_pas_lookup()/qcom_pas_is_loaded(). There is nothing to
 * program here.
 */
static TEE_Result cdsp_dtb_fw_start(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

/*
 * pas_platform_shutdown() (see pas_core.c) refuses to shut this subsystem
 * down while CDSP (PAS_ID_TURING) is still loaded, so there is nothing to
 * enforce here either.
 */
static TEE_Result cdsp_dtb_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

const struct qcom_pas_ops cdsp_dtb_ops = {
	.fw_start = cdsp_dtb_fw_start,
	.fw_shutdown = cdsp_dtb_fw_shutdown,
};
