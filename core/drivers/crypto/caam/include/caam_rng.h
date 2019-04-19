/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2017-2018 NXP
 *
 * @file    caam_rng.h
 *
 * @brief   CAAM Random Number Generator manager header.
 */
#ifndef __CAAM_RNG_H__
#define __CAAM_RNG_H__

/**
 * @brief   Initialize the RNG module and do the instantation of the
 *          State Handles if not done
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_rng_init(vaddr_t ctrl_addr);

/**
 * @brief   Instantiates the RNG State Handles if not already done
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of Memory
 */
enum CAAM_Status caam_rng_instantiation(void);

#endif /* __CAAM_RNG_H__ */

