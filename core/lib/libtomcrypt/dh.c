// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tomcrypt.h>
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
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->y);
	crypto_bignum_free(s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
				     size_t xbits)
{
	TEE_Result res;
	dh_key ltc_tmp_key;
	int ltc_res;

	/* Generate the DH key */
	ltc_tmp_key.g = key->g;
	ltc_tmp_key.p = key->p;
	ltc_res = dh_make_key(NULL, find_prng("prng_crypto"), q, xbits,
			      &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		ltc_mp.copy(ltc_tmp_key.y,  key->y);
		ltc_mp.copy(ltc_tmp_key.x,  key->x);

		/* Free the tempory key */
		dh_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	int err;
	dh_key pk = {
		.type = PK_PRIVATE,
		.g = private_key->g,
		.p = private_key->p,
		.y = private_key->y,
		.x = private_key->x
	};

	err = dh_shared_secret(&pk, public_key, secret);
	return ((err == CRYPT_OK) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS);
}
