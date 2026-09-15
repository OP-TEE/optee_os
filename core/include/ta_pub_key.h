/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef __TA_PUB_KEY_H
#define __TA_PUB_KEY_H

#include <types_ext.h>
#include <utee_defines.h>

/*
 * Main algorithm of the key used to sign TAs, TEE_MAIN_ALGO_RSA or
 * TEE_MAIN_ALGO_ECDSA.
 */
extern const uint32_t ta_pub_key_main_algo;

/* Only valid if @ta_pub_key_main_algo is TEE_MAIN_ALGO_RSA */
extern const uint32_t ta_pub_key_exponent;
extern const uint8_t ta_pub_key_modulus[];
extern const size_t ta_pub_key_modulus_size;

/*
 * Only valid if @ta_pub_key_main_algo is TEE_MAIN_ALGO_ECDSA.
 * @ta_pub_key_ecc_xy holds the public values X and Y concatenated, each of
 * @ta_pub_key_ecc_size bytes.
 */
extern const uint32_t ta_pub_key_ecc_curve;
extern const uint8_t ta_pub_key_ecc_xy[];
extern const size_t ta_pub_key_ecc_size;

/*
 * Returns a binary representation of the public key, the modulus for an RSA
 * key and the concatenated public values X and Y for an ECC key. Used to
 * bind derived keys to the key used to sign TAs.
 */
static inline const uint8_t *ta_pub_key_bin(size_t *size)
{
	if (ta_pub_key_main_algo == TEE_MAIN_ALGO_ECDSA) {
		*size = ta_pub_key_ecc_size * 2;
		return ta_pub_key_ecc_xy;
	}

	*size = ta_pub_key_modulus_size;
	return ta_pub_key_modulus;
}

#endif /*__TA_PUB_KEY_H*/
