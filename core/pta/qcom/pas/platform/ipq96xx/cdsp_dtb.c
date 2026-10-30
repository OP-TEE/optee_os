// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>

#include "cdsp_auth.h"
#include "cdsp_dtb.h"

/* Metadata of the DTB image, authenticated by cdsp_dtb_fw_start(). */
static struct cdsp_metadata cdsp_dtb_md;

static TEE_Result cdsp_dtb_fw_init_image(struct qcom_pas_data *data __unused,
					 void *metadata, size_t size)
{
	return cdsp_metadata_save(&cdsp_dtb_md, metadata, size);
}

/*
 * Pure data image: authenticate it only. cdsp_fw_start() reads its location
 * via qcom_pas_get_fw() once this has succeeded.
 */
static TEE_Result cdsp_dtb_fw_start(struct qcom_pas_data *data __unused)
{
	return cdsp_image_auth(&cdsp_dtb_md, SW_ID_CDSP_DTB);
}

/* Shutdown ordering is enforced by pas_platform_shutdown(). */
static TEE_Result cdsp_dtb_fw_shutdown(struct qcom_pas_data *data __unused)
{
	cdsp_metadata_free(&cdsp_dtb_md);

	return TEE_SUCCESS;
}

const struct qcom_pas_ops cdsp_dtb_ops = {
	.fw_init_image = cdsp_dtb_fw_init_image,
	.fw_start = cdsp_dtb_fw_start,
	.fw_shutdown = cdsp_dtb_fw_shutdown,
};
