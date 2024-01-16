// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Crypto DH interface implementation to enable HW driver.
 */
#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <malloc.h>

TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *key,
					   size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_dh *dh = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Param error key @%#" PRIxPTR " size %zu bits",
			     (uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dh = drvcrypt_get_ops(CRYPTO_DH);
	if (dh)
		ret = dh->alloc_keypair(key, size_bits);

	CRYPTO_TRACE("DH Keypair (%zu bits) alloc ret = 0x%" PRIx32, size_bits,
		     ret);
	return ret;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
				     size_t xbits, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_dh *dh = NULL;

	if (!key) {
		CRYPTO_TRACE("Parameters error key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (key_size != 8 * crypto_bignum_num_bytes(key->p))
		return TEE_ERROR_BAD_PARAMETERS;

	dh = drvcrypt_get_ops(CRYPTO_DH);
	if (dh)
		ret = dh->gen_keypair(key, q, xbits);

	CRYPTO_TRACE("DH Keypair (%zu bits) generate ret = 0x%" PRIx32,
		     key_size, ret);

	return ret;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_dh *dh = NULL;
	struct drvcrypt_secret_data sdata = { };
	uint8_t *secret_buf = NULL;

	if (!private_key || !public_key || !secret) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dh = drvcrypt_get_ops(CRYPTO_DH);
	if (dh) {
		/* Allocate the binary Secret buffer */
		sdata.secret.length = crypto_bignum_num_bytes(private_key->p);
		secret_buf = malloc(sdata.secret.length);
		if (!secret_buf)
			return TEE_ERROR_OUT_OF_MEMORY;

		/* Prepare the Secret structure data */
		sdata.key_priv = private_key;
		sdata.key_pub = public_key;
		sdata.secret.data = secret_buf;

		ret = dh->shared_secret(&sdata);
		if (ret == TEE_SUCCESS)
			ret = crypto_bignum_bin2bn(secret_buf,
						   sdata.secret.length, secret);

		free(secret_buf);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Shared Secret returned 0x%" PRIx32, ret);

	return ret;
}
