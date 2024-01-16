// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s,
					   size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g))
		return TEE_ERROR_OUT_OF_MEMORY;
	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(&s->g);
	crypto_bignum_free(&s->p);
	crypto_bignum_free(&s->y);
	crypto_bignum_free(&s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
				     size_t xbits, size_t key_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	dh_key ltc_tmp_key = { };
	int ltc_res = 0;

	if (key_size != 8 * mp_unsigned_bin_size(key->p))
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_res = mp_init_multi(&ltc_tmp_key.base, &ltc_tmp_key.prime, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Generate the DH key */
	mp_copy(key->g, ltc_tmp_key.base);
	mp_copy(key->p, ltc_tmp_key.prime);
	ltc_res = dh_make_key(NULL, find_prng("prng_crypto"), q, xbits,
			      &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		ltc_mp.copy(ltc_tmp_key.y,  key->y);
		ltc_mp.copy(ltc_tmp_key.x,  key->x);
		res = TEE_SUCCESS;
	}

	dh_free(&ltc_tmp_key);
	return res;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	int err;

	if (!private_key || !public_key || !secret)
		return TEE_ERROR_BAD_PARAMETERS;

	err = mp_exptmod(public_key, private_key->x, private_key->p, secret);
	return ((err == CRYPT_OK) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS);

}
