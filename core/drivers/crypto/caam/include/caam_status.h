/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    caam_status.h
 *
 * @brief   CAAM driver internal status definition
 */

#ifndef __CAAM_STATUS_H__
#define __CAAM_STATUS_H__

/**
 * @brief   Internal CAAM Driver status codes
 */
enum CAAM_Status {
	CAAM_NO_ERROR = 0,   ///< No Error
	CAAM_FAILURE,        ///< General failure
	CAAM_OUT_MEMORY,     ///< Out of memory
	CAAM_BAD_PARAM,      ///< Bad parameters
	CAAM_BUSY,           ///< Operation is not possible, system busy
	CAAM_PENDING,        ///< Operation is pending
	CAAM_TIMEOUT,        ///< Operation timeout
	CAAM_OUT_OF_BOUND,   ///< Value is out of boundary
	CAAM_JOB_STATUS,     ///< A job status is available
};

#endif /* __CAAM_STATUS_H__ */
