// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2021 NXP
 *
 * Brief   Status management utilities.
 */
#include <caam_jr_status.h>
#include <caam_status.h>
#include <caam_utils_status.h>

TEE_Result job_status_to_tee_result(uint32_t status)
{
	/*
	 * Add all status code that can be translated
	 * to a TEE_Result other than TEE_ERROR_GENERIC
	 */
	switch (JRSTA_SRC_GET(status)) {
	case JRSTA_SRC(NONE):
		return TEE_SUCCESS;

	case JRSTA_SRC(DECO):
		if (JRSTA_CCB_GET_ERR(status) == JRSTA_DECO_ERRID_FORMAT)
			return TEE_ERROR_BAD_PARAMETERS;

		if (JRSTA_CCB_GET_ERR(status) == JRSTA_DECO_INV_SIGNATURE)
			return TEE_ERROR_SIGNATURE_INVALID;

		break;

	default:
		break;
	}

	return TEE_ERROR_GENERIC;
}

TEE_Result caam_status_to_tee_result(enum caam_status status)
{
	switch (status) {
	case CAAM_NO_ERROR:
		return TEE_SUCCESS;

	case CAAM_OUT_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case CAAM_BAD_PARAM:
		return TEE_ERROR_BAD_PARAMETERS;

	case CAAM_SHORT_BUFFER:
		return TEE_ERROR_SHORT_BUFFER;

	case CAAM_NOT_SUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;

	default:
		break;
	}

	return TEE_ERROR_GENERIC;
}
