/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    hal_rng.h
 *
 * @brief   CAAM Random Number Generator Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */
#ifndef __HAL_RNG_H__
#define __HAL_RNG_H__

/**
 * @brief   Returns if the RNG HW is already instantiated or not
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  true  RNG is instantiated
 * @retval  false RNG is not instantiated
 */
bool hal_rng_instantiated(vaddr_t baseaddr);

/**
 * @brief   Returns the RNG Status State Handle
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  RNG State Handles status
 */
uint32_t hal_rng_get_statusSH(vaddr_t baseaddr);

/**
 * @brief   Returns the number of RNG State Handle
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  Number of RNG SH
 */
uint32_t hal_rng_get_nbSH(vaddr_t baseaddr);

/**
 * @brief   Returns the RNG Status Key Loade
 *
 * @param[in] baseaddr  RNG Base Address
 *
 * @retval  true   Secure Keys are loaded
 * @retval  false  Secure Keys not are loaded
 */
bool hal_rng_key_loaded(vaddr_t baseaddr);

/**
 * @brief   Configures the RNG entropy delay
 *
 * @param[in] baseaddr   RNG Base Address
 * @param[in] inc_delay  Entropy Delay incrementation
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_OUT_OF_BOUND  Value is out of boundary
 */
enum CAAM_Status hal_rng_kick(vaddr_t baseaddr, uint32_t inc_delay);

#endif /* __HAL_RNG_H__ */

