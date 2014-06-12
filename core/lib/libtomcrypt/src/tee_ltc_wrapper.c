/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "tee_ltc_wrapper.h"
#include "tee_api_defines.h"
#include "tomcrypt_mpa.h"

#define LTC_VARIABLE_NUMBER         (50)

static uint32_t _ltc_mempool_u32[mpa_scratch_mem_size_in_U32(
	LTC_VARIABLE_NUMBER, LTC_MAX_BITS_PER_VARIABLE) ];

static void tee_ltc_alloc_mpa(void)
{
	mpa_scratch_mem pool;
	pool = (mpa_scratch_mem_base *) &_ltc_mempool_u32;
	init_mpa_tomcrypt(pool);
	mpa_init_scratch_mem(pool, LTC_VARIABLE_NUMBER, LTC_MAX_BITS_PER_VARIABLE);
}

static void tee_ltc_dealloc_mpa(void)
{
	/*
	 * Nothing to be done as the memory is static
	 */
}

/* Random generator */
static int prng_mpa_start(prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
	// No entropy is required
	return CRYPT_OK;
}

static int prng_mpa_ready(prng_state *prng)
{
	return CRYPT_OK;
}

extern TEE_Result get_rng_array(void *buf, size_t blen);
static unsigned long prng_mpa_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
	if (TEE_SUCCESS == get_rng_array(out, outlen))
		return outlen;
	else
		return 0;
}

static int prng_mpa_done(prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_import(const unsigned char *in, unsigned long  inlen, prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_test(void)
{
	return CRYPT_OK;
}

static const struct ltc_prng_descriptor prng_mpa_desc =
{
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
 * This function is copied from reg_algs() from libtomcrypt/test/x86_prof.c
 */

static void tee_ltc_reg_algs(void)
{
#ifdef LTC_RIJNDAEL
	register_cipher (&aes_desc);
#endif
#ifdef LTC_BLOWFISH
	register_cipher (&blowfish_desc);
#endif
#ifdef LTC_XTEA
	register_cipher (&xtea_desc);
#endif
#ifdef LTC_RC5
	register_cipher (&rc5_desc);
#endif
#ifdef LTC_RC6
	register_cipher (&rc6_desc);
#endif
#ifdef LTC_SAFERP
	register_cipher (&saferp_desc);
#endif
#ifdef LTC_TWOFISH
	register_cipher (&twofish_desc);
#endif
#ifdef LTC_SAFER
	register_cipher (&safer_k64_desc);
	register_cipher (&safer_sk64_desc);
	register_cipher (&safer_k128_desc);
	register_cipher (&safer_sk128_desc);
#endif
#ifdef LTC_RC2
	register_cipher (&rc2_desc);
#endif
#ifdef LTC_DES
	register_cipher (&des_desc);
	register_cipher (&des3_desc);
#endif
#ifdef LTC_CAST5
	register_cipher (&cast5_desc);
#endif
#ifdef LTC_NOEKEON
	register_cipher (&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
	register_cipher (&skipjack_desc);
#endif
#ifdef LTC_KHAZAD
	register_cipher (&khazad_desc);
#endif
#ifdef LTC_ANUBIS
	register_cipher (&anubis_desc);
#endif
#ifdef LTC_KSEED
	register_cipher (&kseed_desc);
#endif
#ifdef LTC_KASUMI
	register_cipher (&kasumi_desc);
#endif

#ifdef LTC_TIGER
	register_hash (&tiger_desc);
#endif
#ifdef LTC_MD2
	register_hash (&md2_desc);
#endif
#ifdef LTC_MD4
	register_hash (&md4_desc);
#endif
#ifdef LTC_MD5
	register_hash (&md5_desc);
#endif
#ifdef LTC_SHA1
	register_hash (&sha1_desc);
#endif
#ifdef LTC_SHA224
	register_hash (&sha224_desc);
#endif
#ifdef LTC_SHA256
	register_hash (&sha256_desc);
#endif
#ifdef LTC_SHA384
	register_hash (&sha384_desc);
#endif
#ifdef LTC_SHA512
	register_hash (&sha512_desc);
#endif
#ifdef LTC_RIPEMD128
	register_hash (&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
	register_hash (&rmd160_desc);
#endif
#ifdef LTC_RIPEMD256
	register_hash (&rmd256_desc);
#endif
#ifdef LTC_RIPEMD320
	register_hash (&rmd320_desc);
#endif
#ifdef LTC_WHIRLPOOL
	register_hash (&whirlpool_desc);
#endif
#ifdef LTC_CHC_HASH
#error LTC_CHC_HASH is not supported
	register_hash(&chc_desc);
	if ((err = chc_register(register_cipher(&aes_desc))) != CRYPT_OK) {
		fprintf(stderr, "chc_register error: %s\n",
				error_to_string(err));
		exit(EXIT_FAILURE);
	}
#endif

#ifndef LTC_NO_PRNGS
#ifndef LTC_YARROW
#error This demo requires Yarrow.
#endif
	register_prng(&yarrow_desc);
#ifdef LTC_FORTUNA
	register_prng(&fortuna_desc);
#endif
#ifdef LTC_RC4
	register_prng(&rc4_desc);
#endif
#ifdef LTC_SPRNG
	register_prng(&sprng_desc);
#endif

	/*
	if ((err = rng_make_prng(128, find_prng("yarrow"),
	     &yarrow_prng, NULL)) != CRYPT_OK) {
		fprintf(stderr, "rng_make_prng failed: %s\n", error_to_string(err));
		exit(EXIT_FAILURE);
	}
	*/
#endif

	register_prng(&prng_mpa_desc);
}


/*
 * Compute the LibTomCrypt "hashindex" given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - TEE_ERROR_BAD_PARAMETERS in case algo is not a valid algo
 * - TEE_ERROR_NOT_SUPPORTED in case algo is not supported by LTC
 * Return -1 in case of error
 */
TEE_Result tee_algo_to_ltc_hashindex(uint32_t algo, int *ltc_hashindex)
{
	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_SHA1:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_HMAC_SHA1:
		*ltc_hashindex = find_hash("sha1");
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
		*ltc_hashindex = find_hash("md5");
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_SHA224:
	case TEE_ALG_HMAC_SHA224:
		*ltc_hashindex = find_hash("sha224");
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_SHA256:
	case TEE_ALG_HMAC_SHA256:
		*ltc_hashindex = find_hash("sha256");
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
		*ltc_hashindex = find_hash("sha384");
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
		*ltc_hashindex = find_hash("sha512");
		break;

	case TEE_ALG_RSAES_PKCS1_V1_5:
		*ltc_hashindex = -1;	/* invalid one. but it should not be used anyway */
		return TEE_SUCCESS;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (*ltc_hashindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;
}

/*
 * Compute the LibTomCrypt "cipherindex" given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - TEE_ERROR_BAD_PARAMETERS in case algo is not a valid algo
 * - TEE_ERROR_NOT_SUPPORTED in case algo is not supported by LTC
 * Return -1 in case of error
 */
TEE_Result tee_algo_to_ltc_cipherindex(uint32_t algo, int *ltc_cipherindex)
{
	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
		*ltc_cipherindex = find_cipher("aes");
		break;

	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
		*ltc_cipherindex = find_cipher("des");
		break;

	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		*ltc_cipherindex = find_cipher("3des");
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (*ltc_cipherindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;
}

void tee_ltc_init(void)
{
	tee_ltc_alloc_mpa();
	tee_ltc_reg_algs();
}

void tee_ltc_deinit(void)
{
	tee_ltc_dealloc_mpa();
}

/*
 * Get the RNG index to use
 */

int tee_ltc_get_rng_mpa(void)
{
	static int first = 1;
	static int lindex = -1;

	if (first) {
		lindex = find_prng("prng_mpa");
		first = 0;
	}
	return lindex;
}
