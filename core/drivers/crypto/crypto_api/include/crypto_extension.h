/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    crypto_extension.h
 *
 * @brief   This is the Cryptographic API extension.
 */

#ifndef __CRYPTO_EXTENSION_H__
#define __CRYPTO_EXTENSION_H__

#include <tee_api_types.h>
#include <drvcrypt.h>

#ifdef CFG_CRYPTO_DRV_HUK
/**
 * @brief   Generation of the Hardware Unique Key (HUK)
 *
 * @param[out] huk  HUK key generated
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_generate_huk(struct drvcrypt_buf *huk);
#endif

#endif /* __CRYPTO_EXTENSION_H */
