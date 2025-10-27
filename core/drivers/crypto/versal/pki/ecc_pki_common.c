// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022.
 * Author: Jorge Ramirez <jorge@foundries.io>
 *
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#include <crypto/crypto.h>
#include <ecc_pki.h>
#include <ecc.h>
#include <kernel/panic.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <utee_defines.h>

TEE_Result pki_ecc_get_key_size(uint32_t curve, size_t *bytes, size_t *bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P256:
		*bits = 256;
		*bytes = 32;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*bits = 384;
		*bytes = 48;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*bits = 521;
		*bytes = 66;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

void pki_memcpy_swp(uint8_t *to, const uint8_t *from, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		to[i] = from[len - 1 - i];
}

void pki_crypto_bignum_bn2bin_eswap(uint32_t curve,
				    struct bignum *from, uint8_t *to)
{
	uint8_t pad[66] = { 0 };
	size_t len = crypto_bignum_num_bytes(from);
	size_t bytes = 0;
	size_t bits = 0;

	if (pki_ecc_get_key_size(curve, &bytes, &bits))
		panic();

	crypto_bignum_bn2bin(from, pad + bytes - len);
	pki_memcpy_swp(to, pad, bytes);
}

void pki_crypto_bignum_bin2bn_eswap(const uint8_t *from, size_t sz,
				    struct bignum *to)
{
	uint8_t pad[66] = { 0 };

	pki_memcpy_swp(pad, from, sz);
	crypto_bignum_bin2bn(pad, sz, to);
}

TEE_Result pki_ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
			       size_t msg_len, size_t *len, uint8_t *buf)
{
	if (msg_len > TEE_SHA512_HASH_SIZE + 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (algo == TEE_ALG_ECDSA_SHA256)
		*len = TEE_SHA256_HASH_SIZE;
	else if (algo == TEE_ALG_ECDSA_SHA384)
		*len = TEE_SHA384_HASH_SIZE;
	else if (algo == TEE_ALG_ECDSA_SHA512)
		*len = TEE_SHA512_HASH_SIZE + 2;
	else
		return TEE_ERROR_NOT_SUPPORTED;

	/* Swap the hash/message */
	pki_memcpy_swp(buf, msg, msg_len);

	return TEE_SUCCESS;
}
