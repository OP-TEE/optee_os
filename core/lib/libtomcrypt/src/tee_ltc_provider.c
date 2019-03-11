// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_cryp_utl.h>
#include <tomcrypt.h>
#include "tomcrypt_mp.h"
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#if defined(CFG_WITH_VFP)
#include <tomcrypt_arm_neon.h>
#include <kernel/thread.h>
#endif

/* Random generator */
static int prng_mpa_start(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_add_entropy(const unsigned char *in __unused,
				unsigned long inlen __unused,
				union Prng_state *prng __unused)
{
	/* No entropy is required */
	return CRYPT_OK;
}

static int prng_mpa_ready(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static unsigned long prng_mpa_read(unsigned char *out, unsigned long outlen,
				   union Prng_state *prng __unused)
{
	if (crypto_rng_read(out, outlen))
		return 0;

	return outlen;
}

static int prng_mpa_done(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_export(unsigned char *out __unused,
			   unsigned long *outlen __unused,
			   union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_import(const unsigned char *in  __unused,
			   unsigned long inlen __unused,
			   union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_test(void)
{
	return CRYPT_OK;
}

static const struct ltc_prng_descriptor prng_mpa_desc = {
	.name = "prng_mpa",
	.export_size = 64,
	.start = &prng_mpa_start,
	.add_entropy = &prng_mpa_add_entropy,
	.ready = &prng_mpa_ready,
	.read = &prng_mpa_read,
	.done = &prng_mpa_done,
	.pexport = &prng_mpa_export,
	.pimport = &prng_mpa_import,
	.test = &prng_mpa_test,
};

/*
 * tee_ltc_reg_algs(): Registers
 *	- algorithms
 *	- hash
 *	- prng (pseudo random generator)
 */

static void tee_ltc_reg_algs(void)
{
#if defined(CFG_CRYPTO_AES)
	register_cipher(&aes_desc);
#endif
#if defined(CFG_CRYPTO_DES)
	register_cipher(&des_desc);
	register_cipher(&des3_desc);
#endif
#if defined(CFG_CRYPTO_MD5)
	register_hash(&md5_desc);
#endif
#if defined(CFG_CRYPTO_SHA1)
	register_hash(&sha1_desc);
#endif
#if defined(CFG_CRYPTO_SHA224)
	register_hash(&sha224_desc);
#endif
#if defined(CFG_CRYPTO_SHA256)
	register_hash(&sha256_desc);
#endif
#if defined(CFG_CRYPTO_SHA384)
	register_hash(&sha384_desc);
#endif
#if defined(CFG_CRYPTO_SHA512)
	register_hash(&sha512_desc);
#endif
	register_prng(&prng_mpa_desc);
}

TEE_Result crypto_init(void)
{
	init_mp_tomcrypt();
	tee_ltc_reg_algs();

	return TEE_SUCCESS;
}

#if defined(CFG_WITH_VFP)
void tomcrypt_arm_neon_enable(struct tomcrypt_arm_neon_state *state)
{
	state->state = thread_kernel_enable_vfp();
}

void tomcrypt_arm_neon_disable(struct tomcrypt_arm_neon_state *state)
{
	thread_kernel_disable_vfp(state->state);
}
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	hash_state hs;
	uint8_t digest[TEE_SHA256_HASH_SIZE];

	if (sha256_init(&hs) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha256_process(&hs, data, data_size) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha256_done(&hs, digest) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (consttime_memcmp(digest, hash, sizeof(digest)) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
#endif

#if defined(CFG_CRYPTO_SHA512_256)
TEE_Result hash_sha512_256_compute(uint8_t *digest, const uint8_t *data,
		size_t data_size)
{
	hash_state hs;

	if (sha512_256_init(&hs) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha512_256_process(&hs, data, data_size) != CRYPT_OK)
		return TEE_ERROR_GENERIC;
	if (sha512_256_done(&hs, digest) != CRYPT_OK)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif

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
