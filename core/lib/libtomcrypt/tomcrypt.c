// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <crypto/crypto.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <tomcrypt.h>
#include "tomcrypt_mp.h"
#include <trace.h>

#if defined(_CFG_CORE_LTC_VFP)
#include <tomcrypt_arm_neon.h>
#include <kernel/thread.h>
#endif

/* Random generator */
static int prng_crypto_start(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_crypto_add_entropy(const unsigned char *in __unused,
				   unsigned long inlen __unused,
				   union Prng_state *prng __unused)
{
	/* No entropy is required */
	return CRYPT_OK;
}

static int prng_crypto_ready(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static unsigned long prng_crypto_read(unsigned char *out, unsigned long outlen,
				      union Prng_state *prng __unused)
{
	if (crypto_rng_read(out, outlen))
		return 0;

	return outlen;
}

static int prng_crypto_done(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_crypto_export(unsigned char *out __unused,
			      unsigned long *outlen __unused,
			      union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_crypto_import(const unsigned char *in  __unused,
			      unsigned long inlen __unused,
			      union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_crypto_test(void)
{
	return CRYPT_OK;
}

static const struct ltc_prng_descriptor prng_crypto_desc = {
	.name = "prng_crypto",
	.export_size = 64,
	.start = &prng_crypto_start,
	.add_entropy = &prng_crypto_add_entropy,
	.ready = &prng_crypto_ready,
	.read = &prng_crypto_read,
	.done = &prng_crypto_done,
	.pexport = &prng_crypto_export,
	.pimport = &prng_crypto_import,
	.test = &prng_crypto_test,
};

/*
 * tee_ltc_reg_algs(): Registers
 *	- algorithms
 *	- hash
 *	- prng (pseudo random generator)
 */

static void tee_ltc_reg_algs(void)
{
#if defined(_CFG_CORE_LTC_AES) || defined(_CFG_CORE_LTC_AES_DESC)
	register_cipher(&aes_desc);
#endif
#if defined(_CFG_CORE_LTC_DES)
	register_cipher(&des_desc);
	register_cipher(&des3_desc);
#endif
#if defined(_CFG_CORE_LTC_MD5)
	register_hash(&md5_desc);
#endif
#if defined(_CFG_CORE_LTC_SHA1)
	register_hash(&sha1_desc);
#endif
#if defined(_CFG_CORE_LTC_SHA224)
	register_hash(&sha224_desc);
#endif
#if defined(_CFG_CORE_LTC_SHA256) || defined(_CFG_CORE_LTC_SHA256_DESC)
	register_hash(&sha256_desc);
#endif
#if defined(_CFG_CORE_LTC_SHA384) || defined(_CFG_CORE_LTC_SHA384_DESC)
	register_hash(&sha384_desc);
#endif
#if defined(_CFG_CORE_LTC_SHA512) || defined(_CFG_CORE_LTC_SHA512_DESC)
	register_hash(&sha512_desc);
#endif
	register_prng(&prng_crypto_desc);
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
