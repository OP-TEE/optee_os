/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    utils_status.h
 *
 * @brief   Status code management utilities header.
 */
#ifndef __UTILS_STATUS_H__
#define __UTILS_STATUS_H__

#include "caam_common.h"

/**
 * @brief   Convert Job status code to TEE Result
 *
 * @param[in]  status   Job status code
 *
 * @retval TEE_ERROR_GENERIC         Generic error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 */
TEE_Result job_status_to_tee_result(descStatus_t status);

/**
 * @brief   Convert Job status code to CAAM Status
 *
 * @param[in]  status   Job status code
 *
 * @retval CAAM_FAILURE    General failure
 * @retval CAAM_BAD_PARAM  Bad parameters
 */
enum CAAM_Status job_status_to_caam_status(descStatus_t status);

/**
 * @brief   CAAM Status to TEE Result
 *
 * @param[in]  status   CAAM status code
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Generic error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 */
TEE_Result caam_status_to_tee_result(enum CAAM_Status status);

#endif /* __UTILS_STATUS_H__ */
