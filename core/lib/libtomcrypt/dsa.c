// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <tomcrypt.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s,
					    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s,
					       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t key_size)
{
	TEE_Result res;
	dsa_key ltc_tmp_key;
	size_t group_size, modulus_size = key_size/8;
	int ltc_res;

	if (modulus_size <= 128)
		group_size = 20;
	else if (modulus_size <= 256)
		group_size = 30;
	else if (modulus_size <= 384)
		group_size = 35;
	else
		group_size = 40;

	/* Generate the DSA key */
	ltc_res = dsa_make_key(NULL, find_prng("prng_mpa"), group_size,
			       modulus_size, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.p) != key_size) {
		dsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* Copy the key */
		ltc_mp.copy(ltc_tmp_key.g, key->g);
		ltc_mp.copy(ltc_tmp_key.p, key->p);
		ltc_mp.copy(ltc_tmp_key.q, key->q);
		ltc_mp.copy(ltc_tmp_key.y, key->y);
		ltc_mp.copy(ltc_tmp_key.x, key->x);

		/* Free the tempory key */
		dsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result crypto_acipher_dsa_sign(uint32_t algo, struct dsa_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size;
	int ltc_res;
	void *r, *s;
	dsa_key ltc_key = {
		.type = PK_PRIVATE,
		.qord = mp_unsigned_bin_size(key->g),
		.g = key->g,
		.p = key->p,
		.q = key->q,
		.y = key->y,
		.x = key->x,
	};

	if (algo != TEE_ALG_DSA_SHA1 &&
	    algo != TEE_ALG_DSA_SHA224 &&
	    algo != TEE_ALG_DSA_SHA256) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		goto err;
	if (mp_unsigned_bin_size(ltc_key.q) < hash_size)
		hash_size = mp_unsigned_bin_size(ltc_key.q);
	if (msg_len != hash_size) {
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	if (*sig_len < 2 * mp_unsigned_bin_size(ltc_key.q)) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key.q);
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ltc_res = dsa_sign_hash_raw(msg, msg_len, r, s, NULL,
				    find_prng("prng_mpa"), &ltc_key);

	if (ltc_res == CRYPT_OK) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key.q);
		memset(sig, 0, *sig_len);
		mp_to_unsigned_bin(r, (uint8_t *)sig + *sig_len/2 -
				   mp_unsigned_bin_size(r));
		mp_to_unsigned_bin(s, (uint8_t *)sig + *sig_len -
				   mp_unsigned_bin_size(s));
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_GENERIC;
	}

	mp_clear_multi(r, s, NULL);

err:
	return res;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo, struct dsa_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	int ltc_stat, ltc_res;
	void *r, *s;
	dsa_key ltc_key = {
		.type = PK_PUBLIC,
		.qord = mp_unsigned_bin_size(key->g),
		.g = key->g,
		.p = key->p,
		.q = key->q,
		.y = key->y
	};

	if (algo != TEE_ALG_DSA_SHA1 &&
	    algo != TEE_ALG_DSA_SHA224 &&
	    algo != TEE_ALG_DSA_SHA256) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);
	ltc_res = dsa_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, &ltc_key);
	mp_clear_multi(r, s, NULL);
	res = convert_ltc_verify_status(ltc_res, ltc_stat);
err:
	return res;
}
