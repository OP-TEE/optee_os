// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * TME use case: get the antirollback (ARB) version numbers of an image.
 */

#include <drivers/qcom/tme/tme_intf.h>
#include <drivers/qcom/tme/tme_intf_defs.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#include "tme_message.h"
#include "tme_tags.h"

TEE_Result tme_get_arb_version_number(uint32_t sw_id,
				      uint8_t *const oem_version,
				      uint8_t *const qti_version,
				      uint8_t *const oem_is_valid,
				      uint8_t *const qti_is_valid)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct tme_get_arb_version_req req = { .sw_id = sw_id };
	struct tme_get_arb_version_rsp rsp = { };
	size_t response_len = sizeof(rsp);

	if (!oem_version || !qti_version || !oem_is_valid || !qti_is_valid)
		goto bail;

	res = tme_transceive_message(TME_MSG_CBOR_TAG_GET_ARB_VERSION,
				     &req, sizeof(req), &rsp, sizeof(rsp),
				     &response_len);
	if (res != TEE_SUCCESS)
		goto bail;

	if (response_len != sizeof(rsp)) {
		res = TEE_ERROR_GENERIC;
		goto bail;
	}

	*oem_version = rsp.oem_version;
	*qti_version = rsp.qti_version;
	*oem_is_valid = rsp.oem_is_valid;
	*qti_is_valid = rsp.qti_is_valid;

	res = TEE_SUCCESS;

bail:
	return res;
}
