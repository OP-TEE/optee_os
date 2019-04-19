// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    utils_status.c
 *
 * @brief   Status management utilities.
 */

/* Local includes */
#include "jr_status.h"

/* Utils includes */
#include "utils_status.h"

/**
 * @brief   Convert Job status code to TEE Result
 *
 * @param[in]  status   Job status code
 *
 * @retval  TEE_ERROR_GENERIC
 * @retval  TEE_ERROR_BAD_PARAMETERS
 */
TEE_Result job_status_to_tee_result(descStatus_t status)
{
	/*
	 * Add all status code that can be translate
	 * to a TEE result other than TEE_ERROR_GENERIC
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
