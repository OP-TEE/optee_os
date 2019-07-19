/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    caam_huk.h
 *
 * @brief   CAAM HUK manager header
 */
#ifndef __CAAM_HUK_H__
#define __CAAM_HUK_H__

/* Global includes */
#include <tee_api_types.h>

/**
 * @brief   Initialize the HUK module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 */
enum CAAM_Status caam_huk_init(vaddr_t ctrl_addr);

#endif /* __CAAM_HUK_H__ */

