/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    local.h
 *
 * @brief   Definition of the functions shared locally.
 *
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

/* Driver Crypto includes */
#include <drvcrypt_acipher.h>

/**
 * @brief   Mask Generation function. Use a Hash operation
 *          to generate an output \a mask from a input \a seed
 *
 * @param[in/out] mgf_data  MGF data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result rsa_mgf1(struct drvcrypt_rsa_mgf *mgf_data);

/**
 * @brief   PKCS#1 - Signature of RSA message and encodes the signature.
 *
 * @param[in/out]  ssa_data   RSA data to sign / Signature
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result rsassa_sign(struct drvcrypt_rsa_ssa *ssa_data);

/**
 * @brief   PKCS#1 - Verification the encoded signature of RSA message.
 *
 * @param[in]  ssa_data   RSA Encoded signature data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature invalid
 */
TEE_Result rsassa_verify(struct drvcrypt_rsa_ssa *ssa_data);

#endif /* __LOCAL_H__ */

