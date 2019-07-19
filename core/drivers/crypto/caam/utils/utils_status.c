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
 * @retval TEE_ERROR_GENERIC         Generic error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
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

/**
 * @brief   Convert Job status code to CAAM Status
 *
 * @param[in]  status   Job status code
 *
 * @retval CAAM_FAILURE    General failure
 * @retval CAAM_BAD_PARAM  Bad parameters
 */
enum CAAM_Status job_status_to_caam_status(descStatus_t status)
{
	/*
	 * Add all status code that can be translate
	 * to a TEE result other than TEE_ERROR_GENERIC
	 */
	switch (JRSTA_SRC_GET(status)) {
	case JRSTA_SRC(DECO):
		if (JRSTA_CCB_GET_ERR(status) == JRSTA_DECO_ERRID_FORMAT)
			return CAAM_BAD_PARAM;
		break;
	default:
		break;
	}

	return CAAM_FAILURE;
}

/**
 * @brief   CAAM Status to TEE Result
 *
 * @param[in]  status   CAAM status code
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Generic error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 */
TEE_Result caam_status_to_tee_result(enum CAAM_Status status)
{
	switch (status) {
	case CAAM_NO_ERROR:
		return TEE_SUCCESS;

	case CAAM_BAD_PARAM:
		return TEE_ERROR_BAD_PARAMETERS;

	case CAAM_OUT_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	default:
		break;
	}

	return TEE_ERROR_GENERIC;
}
