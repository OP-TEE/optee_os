// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Technology Innovation Institute (TII)
 * Copyright (c) 2022, EPAM Systems
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

#define ED25519_KEY_SIZE UL(256)

TEE_Result crypto_acipher_alloc_ed25519_keypair(struct ed25519_keypair *key,
						size_t key_size)
{
	if (!key || key_size != ED25519_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	key->priv = calloc(1, key_size >> 3);
	key->pub = calloc(1, key_size >> 3);

	if (!key->priv || !key->pub) {
		free(key->priv);
		free(key->pub);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

TEE_Result
crypto_acipher_alloc_ed25519_public_key(struct ed25519_public_key *key,
					size_t key_size)
{
	if (!key || key_size != ED25519_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	key->pub = calloc(1, key_size >> 3);

	if (!key->pub)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_gen_ed25519_key(struct ed25519_keypair *key,
					  size_t key_size)
{
	curve25519_key ltc_tmp_key = { };

	if (key_size != ED25519_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ed25519_make_key(NULL, find_prng("prng_crypto"),
			     &ltc_tmp_key) != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(key_size >= sizeof(ltc_tmp_key.pub) &&
	       key_size >= sizeof(ltc_tmp_key.priv));

	memcpy(key->pub, ltc_tmp_key.pub, sizeof(ltc_tmp_key.pub));
	memcpy(key->priv, ltc_tmp_key.priv, sizeof(ltc_tmp_key.priv));
	memzero_explicit(&ltc_tmp_key, sizeof(ltc_tmp_key));

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_ed25519_sign(struct ed25519_keypair *key,
				       const uint8_t *msg, size_t msg_len,
				       uint8_t *sig, size_t *sig_len)
{
	int err;
	unsigned long siglen = 0;
	curve25519_key private_key = {
		.type = PK_PRIVATE,
		.algo = LTC_OID_ED25519,
	};

	if (!key || !sig_len)
		return TEE_ERROR_BAD_PARAMETERS;

	siglen = *sig_len;

	memcpy(private_key.priv, key->priv, sizeof(private_key.priv));
	memcpy(private_key.pub, key->pub, sizeof(private_key.pub));

	err = ed25519_sign(msg, msg_len, sig, &siglen, &private_key);

	memzero_explicit(&private_key, sizeof(private_key));

	if (err != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;
	*sig_len = siglen;
	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_ed25519ctx_sign(struct ed25519_keypair *key,
					  const uint8_t *msg, size_t msg_len,
					  uint8_t *sig, size_t *sig_len,
					  bool ph_flag,
					  const uint8_t *ctx, size_t ctxlen)
{
	int err = CRYPT_ERROR;
	unsigned long siglen = 0;
	curve25519_key private_key = {
		.type = PK_PRIVATE,
		.algo = LTC_OID_ED25519,
	};

	if (!key || !sig_len)
		return TEE_ERROR_BAD_PARAMETERS;

	siglen = *sig_len;

	memcpy(private_key.priv, key->priv, sizeof(private_key.priv));
	memcpy(private_key.pub, key->pub, sizeof(private_key.pub));

	if (ph_flag) {
		err = ed25519ph_sign(msg, msg_len, sig, &siglen,
				     ctx, ctxlen, &private_key);
	} else {
		err = ed25519ctx_sign(msg, msg_len, sig, &siglen,
				      ctx, ctxlen, &private_key);
	}

	memzero_explicit(&private_key, sizeof(private_key));

	if (err != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;
	*sig_len = siglen;
	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_ed25519_verify(struct ed25519_public_key *key,
					 const uint8_t *msg, size_t msg_len,
					 const uint8_t *sig, size_t sig_len)
{
	int stat = 0;
	curve25519_key public_key = {
		.type = PK_PUBLIC,
		.algo = LTC_OID_ED25519,
	};

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(public_key.pub, key->pub, sizeof(public_key.pub));

	if (ed25519_verify(msg, msg_len, sig, sig_len, &stat,
			   &public_key) != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	if (stat != 1)
		return TEE_ERROR_SIGNATURE_INVALID;

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_ed25519ctx_verify(struct ed25519_public_key *key,
					    const uint8_t *msg, size_t msg_len,
					    const uint8_t *sig, size_t sig_len,
					    bool ph_flag,
					    const uint8_t *ctx, size_t ctxlen)
{
	int stat = 0;
	curve25519_key public_key = {
		.type = PK_PUBLIC,
		.algo = LTC_OID_ED25519,
	};

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(public_key.pub, key->pub, sizeof(public_key.pub));

	if (ph_flag) {
		if (ed25519ph_verify(msg, msg_len, sig, sig_len, ctx, ctxlen,
				     &stat, &public_key) != CRYPT_OK)
			return TEE_ERROR_BAD_PARAMETERS;
	} else {
		if (ed25519ctx_verify(msg, msg_len, sig, sig_len, ctx, ctxlen,
				      &stat, &public_key) != CRYPT_OK)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	if (stat != 1)
		return TEE_ERROR_SIGNATURE_INVALID;

	return TEE_SUCCESS;
}
