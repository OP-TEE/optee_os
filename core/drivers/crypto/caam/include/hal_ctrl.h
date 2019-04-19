/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_ctrl.h
 *
 * @brief   CAAM Controller Hardware Abstration Layer header.
 */
#ifndef __HAL_CTRL_H__
#define __HAL_CTRL_H__

/* Global includes */
#include <utee_defines.h>

/**
 * @brief   Initializes the CAAM HW Controller
 *
 * @param[in] baseaddr  Controller base address
 */
void hal_ctrl_init(vaddr_t baseaddr);

/**
 * @brief   Returns the number of Job Ring supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  The number of Job Ring in HW
 */
uint8_t hal_ctrl_jrnum(vaddr_t baseaddr);

/**
 * @brief   Returns the Maximum Hash supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Maximum Hash Id supported
 * @retval  (-1) if hash is not supported
 */
int hal_ctrl_hash_limit(vaddr_t baseaddr);

/**
 * @brief   Returns if the HW support the split key operation.
 *          Split key is supported if CAAM Version is > 3
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  true  if split key is supported
 * @retval  false otherwise
 */
bool hal_ctrl_splitkey(vaddr_t baseaddr);

/**
 * @brief   Returns the CAAM Era
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Era version
 */
uint8_t hal_ctrl_caam_era(vaddr_t baseaddr);

#endif /* __HAL_CTRL_H__ */
