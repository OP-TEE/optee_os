/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Cryptographic library using the HW crypto driver.
 *         Mathematical operation using HW if available.
 */
#ifndef __DRVCRYPT_MATH_H__
#define __DRVCRYPT_MATH_H__

#include <drvcrypt.h>

/*
 * Binary Modular operation data
 */
struct drvcrypt_mod_op {
	struct drvcrypt_buf n;	    /* Modulus N */
	struct drvcrypt_buf a;	    /* Operand A */
	struct drvcrypt_buf b;	    /* Operand B */
	struct drvcrypt_buf result; /* Result of operation */
};

/*
 * Operation (A xor B) mod N
 *
 * @data   [in/out] Data operation
 */
TEE_Result drvcrypt_xor_mod_n(struct drvcrypt_mod_op *data);

/*
 * Crypto Library Binaries Modular driver operations
 */
struct drvcrypt_math {
	/* (A xor B) mod N */
	TEE_Result (*xor_mod_n)(struct drvcrypt_mod_op *op_data);
};

/*
 * Register a mathematical processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_math(const struct drvcrypt_math *ops)
{
	return drvcrypt_register(CRYPTO_MATH, (void *)ops);
}
#endif /* __DRVCRYPT_MATH_H__ */
