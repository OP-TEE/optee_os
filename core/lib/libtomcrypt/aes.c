// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto_accel.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tomcrypt_private.h>

#define AES_ENC_KEY_LEN	(sizeof(ulong32) * 60)

TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, size_t enc_keylen,
				     unsigned int *rounds)
{
#ifdef _CFG_CORE_LTC_AES_ACCEL
	return crypto_accel_aes_expand_keys(key, key_len, enc_key, NULL,
					    enc_keylen, rounds);
#else
	symmetric_key skey;

	if (enc_keylen < AES_ENC_KEY_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (aes_setup(key, key_len, 0, &skey))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(enc_key, skey.rijndael.eK, AES_ENC_KEY_LEN);
	*rounds = skey.rijndael.Nr;
#endif
	return TEE_SUCCESS;
}

void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen __maybe_unused,
			  unsigned int rounds, const void *src, void *dst)
{
#ifdef _CFG_CORE_LTC_AES_ACCEL
	crypto_accel_aes_ecb_enc(dst, src, enc_key, rounds, 1);
#else
	symmetric_key skey = { };

	assert(enc_keylen >= AES_ENC_KEY_LEN);
	skey.rijndael.eK = LTC_ALIGN_BUF(skey.rijndael.K, 16);
	memcpy(skey.rijndael.eK, enc_key, AES_ENC_KEY_LEN);
	skey.rijndael.Nr = rounds;
	if (aes_ecb_encrypt(src, dst, &skey))
		panic();
#endif
}
