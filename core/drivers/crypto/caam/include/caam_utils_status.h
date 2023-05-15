/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, 2021 NXP
 *
 * Brief   Status code management utilities header.
 */
#ifndef __CAAM_UTILS_STATUS_H__
#define __CAAM_UTILS_STATUS_H__

#include <stdint.h>
#include <tee_api_types.h>

/*
 * Convert Job status code to TEE Result
 *
 * @status   Job status code
 */
TEE_Result job_status_to_tee_result(uint32_t status);

/*
 * Convert caam status code to TEE Result
 *
 * @status   caam status code
 */
TEE_Result caam_status_to_tee_result(enum caam_status status);

#endif /* __CAAM_UTILS_STATUS_H__ */
