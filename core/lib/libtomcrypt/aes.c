// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tomcrypt.h>

TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, size_t enc_keylen,
				     unsigned int *rounds)
{
	symmetric_key skey;

	if (enc_keylen < sizeof(skey.rijndael.eK))
		return TEE_ERROR_BAD_PARAMETERS;

	if (aes_setup(key, key_len, 0, &skey))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(enc_key, skey.rijndael.eK, sizeof(skey.rijndael.eK));
	*rounds = skey.rijndael.Nr;
	return TEE_SUCCESS;
}

void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen __maybe_unused,
			  unsigned int rounds, const void *src, void *dst)
{
	symmetric_key skey;

	assert(enc_keylen >= sizeof(skey.rijndael.eK));
	memcpy(skey.rijndael.eK, enc_key, sizeof(skey.rijndael.eK));
	skey.rijndael.Nr = rounds;
	if (aes_ecb_encrypt(src, dst, &skey))
		panic();
}
