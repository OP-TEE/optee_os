// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   Status management utilities.
 */
#include <caam_jr_status.h>
#include <caam_utils_status.h>

TEE_Result job_status_to_tee_result(uint32_t status)
{
	/*
	 * Add all status code that can be translated
	 * to a TEE_Result other than TEE_ERROR_GENERIC
	 */
	switch (JRSTA_SRC_GET(status)) {
	case JRSTA_SRC(DECO):
		if (JRSTA_CCB_GET_ERR(status) == JRSTA_DECO_ERRID_FORMAT)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		break;
	}

	return TEE_ERROR_GENERIC;
}
