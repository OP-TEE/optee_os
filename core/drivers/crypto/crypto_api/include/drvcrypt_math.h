/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    drvcrypt_math.h
 *
 * @brief   Cryptographic library using the HW crypto driver.\n
 *          Mathematical operation using HW if available.
 */
#ifndef __DRVCRYPT_MATH_H__
#define __DRVCRYPT_MATH_H__

/**
 * @brief   Binary Modular operation data
 */
struct drvcrypt_mod_op {
	struct drvcrypt_buf N;      ///< Modulus N
	struct drvcrypt_buf A;      ///< Operand A
	struct drvcrypt_buf B;      ///< Operand B
	struct drvcrypt_buf result; ///< Result of operation
};

/**
 * @brief   operation (A xor B) mod N
 *
 * @param[in/out] data   input/output data operation
 *
 * @retval TEE_SUCCESS               Operation success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_GENERIC         Operation failed
 */
TEE_Result drvcrypt_xor_mod_n(struct drvcrypt_mod_op *data);

/**
 * @brief   NXP Crypto Library Binaries Modular driver operations
 *
 */
struct drvcrypt_math {
	///< (A xor B) mod N
	TEE_Result (*xor_mod_n)(struct drvcrypt_mod_op *op_data);
};

#endif /* __DRVCRYPT_MATH_H__ */
