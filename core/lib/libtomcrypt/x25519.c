// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Technology Innovation Institute (TII)
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

/* X25519 key is an octet string of 32 bytes */
#define X25519_KEY_SIZE_BYTES UL(32)

TEE_Result crypto_acipher_alloc_x25519_keypair(struct montgomery_keypair *key,
					       size_t key_size)
{
	size_t key_size_bytes = key_size / 8;

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	if (key_size_bytes != X25519_KEY_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	key->priv = calloc(1, key_size_bytes);
	key->pub = calloc(1, key_size_bytes);

	if (!key->priv || !key->pub) {
		free(key->priv);
		free(key->pub);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_gen_x25519_key(struct montgomery_keypair *key,
					 size_t key_size)
{
	curve25519_key ltc_tmp_key = { };
	size_t key_size_bytes = key_size / 8;

	if (key_size_bytes != X25519_KEY_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	if (x25519_make_key(NULL, find_prng("prng_crypto"), &ltc_tmp_key) !=
	    CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_size_bytes < sizeof(ltc_tmp_key.pub) ||
	    key_size_bytes < sizeof(ltc_tmp_key.priv))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(key->pub, ltc_tmp_key.pub, sizeof(ltc_tmp_key.pub));
	memcpy(key->priv, ltc_tmp_key.priv, sizeof(ltc_tmp_key.priv));
	memzero_explicit(&ltc_tmp_key, sizeof(ltc_tmp_key));

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_x25519_shared_secret(struct montgomery_keypair
					       *private_key,
					       void *public_key,
					       void *secret,
					       unsigned long *secret_len)
{
	curve25519_key ltc_private_key = {
		.type = PK_PRIVATE,
		.algo = LTC_OID_X25519,
	};
	curve25519_key ltc_public_key = {
		.type = PK_PUBLIC,
		.algo = LTC_OID_X25519,
	};

	if (!private_key || !public_key || !secret || !secret_len)
		return TEE_ERROR_BAD_PARAMETERS;

	static_assert(sizeof(ltc_public_key.pub) == X25519_KEY_SIZE_BYTES &&
		      sizeof(ltc_public_key.priv) == X25519_KEY_SIZE_BYTES);

	memcpy(ltc_public_key.pub, public_key, X25519_KEY_SIZE_BYTES);
	memcpy(ltc_private_key.priv, private_key->priv, X25519_KEY_SIZE_BYTES);

	if (x25519_shared_secret(&ltc_private_key, &ltc_public_key,
				 secret, secret_len) != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Clear private key from the stack */
	memzero_explicit(&ltc_private_key, sizeof(ltc_private_key));

	/*
	 * RFC 7748, sec 6.1, check for all zero shared secret output to reject
	 * input points of low order.
	 */
	if (*secret_len != X25519_KEY_SIZE_BYTES ||
	    !consttime_memcmp(secret, ltc_private_key.pub,
			       X25519_KEY_SIZE_BYTES))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
