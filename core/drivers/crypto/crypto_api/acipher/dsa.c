// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Crypto DSA interface implementation to enable HW driver.
 */
#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>

/*
 * Get the recommended L and N bits parameters corresponding
 * respectively to the size of the Primes P and G (and so
 * the Public Key and Private Key).
 *
 * Refer the NIST.FIPS 186-4 section 4.2
 *
 * @size_bits   Maximum key size bits
 * @l_bits      [out] L size in bits
 * @n_bits      [out] N size in bits
 */
static TEE_Result get_keys_size(size_t size_bits, size_t *l_bits,
				size_t *n_bits)
{
	if (size_bits <= 1024)
		*n_bits = 160;
	else if (size_bits <= 3072)
		*n_bits = 256;
	else
		return TEE_ERROR_NOT_IMPLEMENTED;

	*l_bits = size_bits;

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *key,
					    size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_dsa *dsa = NULL;
	size_t l_bits = 0;
	size_t n_bits = 0;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Param error key @0x%" PRIxPTR " size %zu bits",
			     (uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = get_keys_size(size_bits, &l_bits, &n_bits);
	if (ret == TEE_SUCCESS) {
		dsa = drvcrypt_get_ops(CRYPTO_DSA);
		if (dsa)
			ret = dsa->alloc_keypair(key, l_bits, n_bits);
		else
			ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("DSA Keypair (%zu bits) alloc ret = 0x%" PRIx32, size_bits,
		     ret);
	return ret;
}

TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *key,
					       size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_dsa *dsa = NULL;
	size_t l_bits = 0;
	size_t n_bits = 0;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Param error key @0x%" PRIxPTR " size %zu bits",
			     (uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = get_keys_size(size_bits, &l_bits, &n_bits);
	if (ret == TEE_SUCCESS) {
		dsa = drvcrypt_get_ops(CRYPTO_DSA);
		if (dsa)
			ret = dsa->alloc_publickey(key, l_bits, n_bits);
		else
			ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("DSA Public Key (%zu bits) alloc ret = 0x%" PRIx32,
		     size_bits, ret);
	return ret;
}

TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_dsa *dsa = NULL;
	size_t l_bits = 0;
	size_t n_bits = 0;

	if (!key || !key_size) {
		CRYPTO_TRACE("Param error key @0x%" PRIxPTR " size %zu bits",
			     (uintptr_t)key, key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = get_keys_size(key_size, &l_bits, &n_bits);
	if (ret == TEE_SUCCESS) {
		dsa = drvcrypt_get_ops(CRYPTO_DSA);
		if (dsa)
			ret = dsa->gen_keypair(key, l_bits, n_bits);
		else
			ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("DSA Keypair (%zu bits) generate ret = 0x%" PRIx32,
		     key_size, ret);

	return ret;
}

TEE_Result crypto_acipher_dsa_sign(uint32_t algo, struct dsa_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_dsa *dsa = NULL;
	struct drvcrypt_sign_data sdata = { };
	size_t l_bytes = 0;
	size_t n_bytes = 0;

	if (!key || !msg || !sig || !sig_len) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Verify the signature length function of the key size
	 *
	 * Prime number sizes are not stored but deducted from bignum size.
	 * This requires prime numbers p and q to have their MSB set otherwise
	 * crypto_bignum_num_bytes() will return a wrong size.
	 */
	n_bytes = crypto_bignum_num_bytes(key->q);
	l_bytes = crypto_bignum_num_bytes(key->p);
	if (*sig_len < 2 * n_bytes) {
		CRYPTO_TRACE("Length (%zu) too short expected %zu bytes",
			     *sig_len, 2 * n_bytes);
		*sig_len = 2 * n_bytes;
		return TEE_ERROR_SHORT_BUFFER;
	}

	dsa = drvcrypt_get_ops(CRYPTO_DSA);
	if (dsa) {
		sdata.algo = algo;
		sdata.key = key;
		sdata.size_sec = n_bytes;
		sdata.message.data = (uint8_t *)msg;
		sdata.message.length = msg_len;
		sdata.signature.data = sig;
		sdata.signature.length = *sig_len;

		ret = dsa->sign(&sdata, l_bytes, n_bytes);

		/* Set the signature length */
		*sig_len = sdata.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Sign algo (0x%" PRIx32 ") returned 0x%" PRIx32, algo,
		     ret);

	return ret;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo, struct dsa_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_dsa *dsa = NULL;
	struct drvcrypt_sign_data sdata = { };
	size_t l_bytes = 0;
	size_t n_bytes = 0;

	if (!key || !msg || !sig) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Verify the signature length function of the key size
	 *
	 * Prime number sizes are not stored but deducted from bignum size.
	 * This requires prime numbers p and q to have their MSB set otherwise
	 * crypto_bignum_num_bytes() will return a wrong size.
	 */
	n_bytes = crypto_bignum_num_bytes(key->q);
	l_bytes = crypto_bignum_num_bytes(key->p);
	if (sig_len != 2 * n_bytes) {
		CRYPTO_TRACE("Length (%zu) is invalid expected %zu bytes",
			     sig_len, 2 * n_bytes);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	dsa = drvcrypt_get_ops(CRYPTO_DSA);
	if (dsa) {
		sdata.algo = algo;
		sdata.key = key;
		sdata.size_sec = n_bytes;
		sdata.message.data = (uint8_t *)msg;
		sdata.message.length = msg_len;
		sdata.signature.data = (uint8_t *)sig;
		sdata.signature.length = sig_len;

		ret = dsa->verify(&sdata, l_bytes, n_bytes);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Verify algo (0x%" PRIx32 ") returned 0x%" PRIx32, algo,
		     ret);

	return ret;
}
