// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * TME use case: antirollback version commit.
 */

#include <drivers/qcom/tme/tme_intf.h>
#include <drivers/qcom/tme/tme_intf_defs.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#include "tme_message.h"
#include "tme_tags.h"

TEE_Result tme_update_rollback_version(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	tmeUpdateRollbackVersionRsp_t rsp = { };
	size_t response_len = sizeof(rsp);

	/* Empty request payload - see tmeUpdateRollbackVersionRsp_t. */
	res = tme_transceive_message(TME_MSG_CBOR_TAG_UPDATE_ROLLBACK_VERSION,
				     NULL, 0, &rsp, sizeof(rsp),
				     &response_len);
	if (res != TEE_SUCCESS)
		goto bail;

	if (response_len != sizeof(rsp)) {
		res = TEE_ERROR_GENERIC;
		goto bail;
	}

	res = (rsp.status == 0U) ? TEE_SUCCESS : TEE_ERROR_GENERIC;

bail:
	return res;
}
