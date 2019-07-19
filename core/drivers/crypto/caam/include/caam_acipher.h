/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-209 NXP
 *
 * @file    caam_acipher.h
 *
 * @brief   CAAM Asymmetric Cipher manager header.
 */
#ifndef __CAAM_ACIPHER_H__
#define __CAAM_ACIPHER_H__

/* Global Common includes */
#include <types_ext.h>

#ifdef CFG_CRYPTO_ECC_HW
/**
 * @brief   Initialize the ECC module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_ecc_init(vaddr_t ctrl_addr);
#endif

#ifdef CFG_CRYPTO_RSA_HW
/**
 * @brief   Initialize the RSA module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_rsa_init(vaddr_t ctrl_addr);
#endif

/**
 * @brief   Initialize the MATH module
 *l
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_math_init(vaddr_t ctrl_addr);

#endif /* __CAAM_ACIPHER_H__ */

