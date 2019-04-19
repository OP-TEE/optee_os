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
 * @retval  TEE_ERROR_GENERIC
 * @retval  TEE_ERROR_BAD_PARAMETERS
 */
TEE_Result job_status_to_tee_result(descStatus_t status);

#endif /* __UTILS_STATUS_H__ */
