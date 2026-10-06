// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <rpmi.h>
#include <tee_api_defines_extensions.h>

TEE_Result rpmi_status_to_tee_result(int32_t status)
{
	switch (status) {
	case RPMI_SUCCESS:
		return TEE_SUCCESS;
	case RPMI_ERR_NOTSUPP:
		return TEE_ERROR_NOT_SUPPORTED;
	case RPMI_ERR_INVALID_PARAM:
	case RPMI_ERR_INVALID_ADDR:
	case RPMI_ERR_BAD_RANGE:
		return TEE_ERROR_BAD_PARAMETERS;
	case RPMI_ERR_DENIED:
		return TEE_ERROR_ACCESS_DENIED;
	case RPMI_ERR_ALREADY:
	case RPMI_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case RPMI_ERR_BUSY:
		return TEE_ERROR_BUSY;
	case RPMI_ERR_TIMEOUT:
		return TEE_ERROR_TIMEOUT;
	case RPMI_ERR_IO:
		return TEE_ERROR_COMMUNICATION;
	case RPMI_ERR_NO_DATA:
		return TEE_ERROR_NO_DATA;
	default:
		return TEE_ERROR_GENERIC;
	}
}
