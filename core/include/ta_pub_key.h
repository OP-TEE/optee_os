/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef __TA_PUB_KEY_H
#define __TA_PUB_KEY_H

#include <types_ext.h>
#include <utee_defines.h>

/*
 * Public key used to verify TAs. @main_algo is TEE_MAIN_ALGO_RSA or
 * TEE_MAIN_ALGO_ECDSA and selects the corresponding member of the union.
 * @bin holds the RSA modulus or the ECC public values X and Y concatenated,
 * each of @ecc.xy_size bytes.
 */
struct ta_pub_key {
	uint32_t main_algo;
	union {
		struct {
			uint32_t exponent;
			size_t modulus_size;
		} rsa;
		struct {
			uint32_t curve;
			size_t xy_size;
		} ecc;
	};
	uint8_t bin[];
};

extern const struct ta_pub_key ta_pub_key;

/*
 * Returns a binary representation of the public key, the modulus for an RSA
 * key and the concatenated public values X and Y for an ECC key. Used to
 * bind derived keys to the key used to sign TAs.
 */
static inline const uint8_t *ta_pub_key_bin(size_t *size)
{
	if (ta_pub_key.main_algo == TEE_MAIN_ALGO_ECDSA)
		*size = ta_pub_key.ecc.xy_size * 2;
	else
		*size = ta_pub_key.rsa.modulus_size;

	return ta_pub_key.bin;
}

#endif /*__TA_PUB_KEY_H*/
