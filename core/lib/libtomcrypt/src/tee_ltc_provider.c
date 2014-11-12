/*
 * Copyright (c) 2014, Linaro Limited
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

#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>

#include <tomcrypt.h>
#include <mpalib.h>
#include <stdlib.h>
#include <string.h>
#include <utee_defines.h>
#include <trace.h>
#include <tee_api_types.h>
#include <string_ext.h>
#include "tomcrypt_mpa.h"

#define LTC_MAX_BITS_PER_VARIABLE   (4096)
#define LTC_VARIABLE_NUMBER         (50)

static uint32_t _ltc_mempool_u32[mpa_scratch_mem_size_in_U32(
	LTC_VARIABLE_NUMBER, LTC_MAX_BITS_PER_VARIABLE)];

static void tee_ltc_alloc_mpa(void)
{
	mpa_scratch_mem pool = (void *)_ltc_mempool_u32;

	init_mpa_tomcrypt(pool);
	mpa_init_scratch_mem(pool, LTC_VARIABLE_NUMBER,
			     LTC_MAX_BITS_PER_VARIABLE);
}

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
	if (TEE_SUCCESS == get_rng_array(out, outlen))
		return outlen;
	else
		return 0;
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
 * This function is copied from reg_algs() from libtomcrypt/test/x86_prof.c
 */

static void tee_ltc_reg_algs(void)
{
#ifdef LTC_RIJNDAEL
	register_cipher(&aes_desc);
#endif
#ifdef LTC_BLOWFISH
	register_cipher(&blowfish_desc);
#endif
#ifdef LTC_XTEA
	register_cipher(&xtea_desc);
#endif
#ifdef LTC_RC5
	register_cipher(&rc5_desc);
#endif
#ifdef LTC_RC6
	register_cipher(&rc6_desc);
#endif
#ifdef LTC_SAFERP
	register_cipher(&saferp_desc);
#endif
#ifdef LTC_TWOFISH
	register_cipher(&twofish_desc);
#endif
#ifdef LTC_SAFER
	register_cipher(&safer_k64_desc);
	register_cipher(&safer_sk64_desc);
	register_cipher(&safer_k128_desc);
	register_cipher(&safer_sk128_desc);
#endif
#ifdef LTC_RC2
	register_cipher(&rc2_desc);
#endif
#ifdef LTC_DES
	register_cipher(&des_desc);
	register_cipher(&des3_desc);
#endif
#ifdef LTC_CAST5
	register_cipher(&cast5_desc);
#endif
#ifdef LTC_NOEKEON
	register_cipher(&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
	register_cipher(&skipjack_desc);
#endif
#ifdef LTC_KHAZAD
	register_cipher(&khazad_desc);
#endif
#ifdef LTC_ANUBIS
	register_cipher(&anubis_desc);
#endif
#ifdef LTC_KSEED
	register_cipher(&kseed_desc);
#endif
#ifdef LTC_KASUMI
	register_cipher(&kasumi_desc);
#endif

#ifdef LTC_TIGER
	register_hash(&tiger_desc);
#endif
#ifdef LTC_MD2
	register_hash(&md2_desc);
#endif
#ifdef LTC_MD4
	register_hash(&md4_desc);
#endif
#ifdef LTC_MD5
	register_hash(&md5_desc);
#endif
#ifdef LTC_SHA1
	register_hash(&sha1_desc);
#endif
#ifdef LTC_SHA224
	register_hash(&sha224_desc);
#endif
#ifdef LTC_SHA256
	register_hash(&sha256_desc);
#endif
#ifdef LTC_SHA384
	register_hash(&sha384_desc);
#endif
#ifdef LTC_SHA512
	register_hash(&sha512_desc);
#endif
#ifdef LTC_RIPEMD128
	register_hash(&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
	register_hash(&rmd160_desc);
#endif
#ifdef LTC_RIPEMD256
	register_hash(&rmd256_desc);
#endif
#ifdef LTC_RIPEMD320
	register_hash(&rmd320_desc);
#endif
#ifdef LTC_WHIRLPOOL
	register_hash(&whirlpool_desc);
#endif
#ifdef LTC_CHC_HASH
#error LTC_CHC_HASH is not supported
	register_hash(&chc_desc);
	err = chc_register(register_cipher(&aes_desc);
	if (err != CRYPT_OK) {
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
		fprintf(stderr, "rng_make_prng failed: %s\n",
			error_to_string(err));
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
static TEE_Result tee_algo_to_ltc_hashindex(uint32_t algo, int *ltc_hashindex)
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
		/* invalid one. but it should not be used anyway */
		*ltc_hashindex = -1;
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
static TEE_Result tee_algo_to_ltc_cipherindex(uint32_t algo,
					      int *ltc_cipherindex)
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

static TEE_Result tee_ltc_init(void)
{
	tee_ltc_alloc_mpa();
	tee_ltc_reg_algs();
	return TEE_SUCCESS;
}

/*
 * Get the RNG index to use
 */
static int tee_ltc_get_rng_mpa(void)
{
	static int first = 1;
	static int lindex = -1;

	if (first) {
		lindex = find_prng("prng_mpa");
		first = 0;
	}
	return lindex;
}

/******************************************************************************
 * Message digest functions
 ******************************************************************************/

#define MAX_DIGEST 64

static TEE_Result hash_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		*size = sizeof(hash_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result hash_init(void *ctx, uint32_t algo)
{
	int ltc_res;
	int ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex].init(ctx) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result hash_update(void *ctx, uint32_t algo,
				      const uint8_t *data, size_t len)
{
	int ltc_res;
	int ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex].process(ctx, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result hash_final(void *ctx, uint32_t algo, uint8_t *digest,
				     size_t len)
{
	int ltc_res;
	int ltc_hashindex;
	size_t hash_size;
	uint8_t block_digest[MAX_DIGEST];
	uint8_t *tmp_digest;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_size = hash_descriptor[ltc_hashindex].hashsize;
	if ((hash_size < len) || (hash_size > MAX_DIGEST)) {
		/*
		 * Caller is asking for more bytes than the computation
		 * will produce ... might be something wrong
		 */
		return  TEE_ERROR_BAD_PARAMETERS;
	}

	if (hash_size > len)
		tmp_digest = block_digest; /* use a tempory buffer */
	else
		tmp_digest = digest;

	if (hash_descriptor[ltc_hashindex].done(ctx, tmp_digest) == CRYPT_OK) {
		if (hash_size > len)
			memcpy(digest, tmp_digest, len);
	} else {
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/


static size_t num_bytes(struct bignum *a)
{
	return mp_unsigned_bin_size(a);
}

static void bn2bin(const struct bignum *from, uint8_t *to)
{
	mp_to_unsigned_bin((struct bignum *)from, to);
}

static TEE_Result bin2bn(const uint8_t *from, size_t fromsize,
			 struct bignum *to)
{
	if (mp_read_unsigned_bin(to, (uint8_t *)from, fromsize) != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

static void copy(struct bignum *to, const struct bignum *from)
{
	mp_copy((void *)from, to);
}

static struct bignum *bn_allocate(size_t size_bits)
{
	size_t sz = mpa_StaticVarSizeInU32(size_bits) *	sizeof(uint32_t);
	struct mpa_numbase_struct *bn = calloc(1, sz);

	if (!bn)
		return NULL;
	bn->alloc = sz - MPA_NUMBASE_METADATA_SIZE_IN_U32 * sizeof(uint32_t);
	return (struct bignum *)bn;
}

static void bn_free(struct bignum *s)
{
	free(s);
}

static void bn_clear(struct bignum *s)
{
	struct mpa_numbase_struct *bn = (struct mpa_numbase_struct *)s;

	memset(bn, 0, bn->alloc);
}

static bool bn_alloc_max(struct bignum **s)
{
	size_t sz = mpa_StaticVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE) *
			sizeof(uint32_t) * 8;

	*s = bn_allocate(sz);
	return !!(*s);
}

static TEE_Result alloc_rsa_keypair(struct rsa_keypair *s,
				    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->n))
		goto err;
	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	if (!bn_alloc_max(&s->qp))
		goto err;
	if (!bn_alloc_max(&s->dp))
		goto err;
	if (!bn_alloc_max(&s->dq))
		goto err;
	return TEE_SUCCESS;
err:
	bn_free(s->e);
	bn_free(s->d);
	bn_free(s->n);
	bn_free(s->p);
	bn_free(s->q);
	bn_free(s->qp);
	bn_free(s->dp);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_rsa_public_key(struct rsa_public_key *s,
				       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	if (!bn_alloc_max(&s->n))
		goto err;
	return TEE_SUCCESS;
err:
	bn_free(s->e);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_dsa_keypair(struct dsa_keypair *s,
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
	bn_free(s->g);
	bn_free(s->p);
	bn_free(s->q);
	bn_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_dsa_public_key(struct dsa_public_key *s,
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
	bn_free(s->g);
	bn_free(s->p);
	bn_free(s->q);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result alloc_dh_keypair(struct dh_keypair *s,
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
	bn_free(s->g);
	bn_free(s->p);
	bn_free(s->y);
	bn_free(s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result res;
	rsa_key ltc_tmp_key;
	int ltc_res;

	/* Generate a temporary RSA key */
	ltc_res = rsa_make_key(0, tee_ltc_get_rng_mpa(), key_size/8, 65537,
			       &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.N) != key_size) {
		rsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* Copy the key */
		ltc_mp.copy(ltc_tmp_key.e,  key->e);
		ltc_mp.copy(ltc_tmp_key.d,  key->d);
		ltc_mp.copy(ltc_tmp_key.N,  key->n);
		ltc_mp.copy(ltc_tmp_key.p,  key->p);
		ltc_mp.copy(ltc_tmp_key.q,  key->q);
		ltc_mp.copy(ltc_tmp_key.qP, key->qp);
		ltc_mp.copy(ltc_tmp_key.dP, key->dp);
		ltc_mp.copy(ltc_tmp_key.dQ, key->dq);

		/* Free the temporary key */
		rsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

static TEE_Result gen_dh_key(struct dh_keypair *key, struct bignum *q,
			     size_t xbits)
{
	TEE_Result res;
	dh_key ltc_tmp_key;
	int ltc_res;

	/* Generate the DH key */
	ltc_tmp_key.g = key->g;
	ltc_tmp_key.p = key->p;
	ltc_res = dh_make_key(0, tee_ltc_get_rng_mpa(), q, xbits,
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

static TEE_Result gen_dsa_key(struct dsa_keypair *key, size_t key_size)
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
	ltc_res = dsa_make_key(0, tee_ltc_get_rng_mpa(), group_size,
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

static TEE_Result do_dh_shared_secret(struct dh_keypair *private_key,
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

static TEE_Result rsadorep(rsa_key *ltc_key, const uint8_t *src,
			   size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	unsigned long blen, offset;
	int ltc_res;

	/*
	 * Use a temporary buffer since we don't know exactly how large the
	 * required size of the out buffer without doing a partial decrypt.
	 * We know the upper bound though.
	 */
	blen = (mpa_StaticTempVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE)) *
	       sizeof(uint32_t);
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_exptmod(src, src_len, buf, &blen, ltc_key->type,
			      ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_NOT_PRIVATE:
	case CRYPT_PK_INVALID_TYPE:
	case CRYPT_PK_INVALID_SIZE:
	case CRYPT_INVALID_PACKET:
		EMSG("rsa_exptmod() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_exptmod() returned %d\n", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < blen - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < blen - offset) {
		*dst_len = blen - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = TEE_SUCCESS;
	*dst_len = blen - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);

out:
	if (buf)
		free(buf);

	return res;
}

static TEE_Result rsanopad_encrypt(struct rsa_public_key *key,
				   const uint8_t *src, size_t src_len,
				   uint8_t *dst, size_t *dst_len)
{
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PUBLIC;
	ltc_key.e = key->e;
	ltc_key.N = key->n;

	return rsadorep(&ltc_key, src, src_len, dst, dst_len);
}

static TEE_Result rsanopad_decrypt(struct rsa_keypair *key,
				   const uint8_t *src, size_t src_len,
				   uint8_t *dst, size_t *dst_len)
{
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.N = key->n;
	ltc_key.d = key->d;
	if (key->p && num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	return rsadorep(&ltc_key, src, src_len, dst, dst_len);
}

static TEE_Result rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
				    const uint8_t *label, size_t label_len,
				    const uint8_t *src, size_t src_len,
				    uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *buf = NULL;
	unsigned long blen;
	int ltc_hashindex, ltc_res, ltc_stat, ltc_rsa_algo;
	size_t mod_size;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.d = key->d;
	ltc_key.N = key->n;
	if (key->p && num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		goto out;
	}

	/*
	 * Use a temporary buffer since we don't know exactly how large
	 * the required size of the out buffer without doing a partial
	 * decrypt. We know the upper bound though.
	 */
	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		mod_size = ltc_mp.unsigned_size((void *)(ltc_key.N));
		blen = mod_size - 11;
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
	} else {
		/* Decoded message is always shorter than encrypted message */
		blen = src_len;
		ltc_rsa_algo = LTC_LTC_PKCS_1_OAEP;
	}

	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_decrypt_key_ex(src, src_len, buf, &blen,
				     ((label_len == 0) ? 0 : label), label_len,
				     ltc_hashindex, ltc_rsa_algo, &ltc_stat,
				     &ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_decrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	if (ltc_stat != 1) {
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d and %d\n",
		     ltc_res, ltc_stat);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (*dst_len < blen) {
		*dst_len = blen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = TEE_SUCCESS;
	*dst_len = blen;
	memcpy(dst, buf, blen);

out:
	if (buf)
		free(buf);

	return res;
}

static TEE_Result rsaes_encrypt(uint32_t algo, struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result res;
	uint32_t mod_size;
	int ltc_hashindex, ltc_res, ltc_rsa_algo;
	rsa_key ltc_key = {
		.type = PK_PUBLIC,
		.e = key->e,
		.N = key->n
	};

	mod_size =  ltc_mp.unsigned_size((void *)(ltc_key.N));
	if (*dst_len < mod_size) {
		*dst_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_len = mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		goto out;
	}

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5)
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
	else
		ltc_rsa_algo = LTC_LTC_PKCS_1_OAEP;

	ltc_res = rsa_encrypt_key_ex(src, src_len, dst,
				     (unsigned long *)(dst_len), label,
				     label_len, 0, tee_ltc_get_rng_mpa(),
				     ltc_hashindex, ltc_rsa_algo, &ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = TEE_SUCCESS;

out:
	return res;
}

static TEE_Result rsassa_sign(uint32_t algo, struct rsa_keypair *key,
			      int salt_len, const uint8_t *msg,
			      size_t msg_len, uint8_t *sig,
			      size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size, mod_size;
	int ltc_res, ltc_rsa_algo, ltc_hashindex;
	unsigned long ltc_sig_len;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.N = key->n;
	ltc_key.d = key->d;
	if (key->p && num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_PSS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		return res;

	if (msg_len != hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mod_size = ltc_mp.unsigned_size((void *)(ltc_key.N));

	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ltc_sig_len = mod_size;

	ltc_res = rsa_sign_hash_ex(msg, msg_len, sig, &ltc_sig_len,
				   ltc_rsa_algo, 0, tee_ltc_get_rng_mpa(),
				   ltc_hashindex, salt_len, &ltc_key);

	*sig_len = ltc_sig_len;

	if (ltc_res != CRYPT_OK) {
		EMSG("rsa_sign_hash_ex() returned %d\n", ltc_res);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result rsassa_verify(uint32_t algo, struct rsa_public_key *key,
				int salt_len, const uint8_t *msg,
				size_t msg_len, const uint8_t *sig,
				size_t sig_len)
{
	TEE_Result res;
	uint32_t bigint_size;
	int stat, ltc_hashindex, ltc_res, ltc_rsa_algo;
	rsa_key ltc_key = {
		.type = PK_PUBLIC,
		.e = key->e,
		.N = key->n
	};

	bigint_size = ltc_mp.unsigned_size(ltc_key.N);
	if (sig_len < bigint_size)
		return TEE_ERROR_SIGNATURE_INVALID;


	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		return res;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_PSS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = rsa_verify_hash_ex(sig, sig_len, msg, msg_len, ltc_rsa_algo,
				     ltc_hashindex, salt_len, &stat, &ltc_key);
	if ((ltc_res != CRYPT_OK) || (stat != 1)) {
		EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	return TEE_SUCCESS;
}

static TEE_Result dsa_sign(uint32_t algo, struct dsa_keypair *key,
			   const uint8_t *msg, size_t msg_len, uint8_t *sig,
			   size_t *sig_len)
{
	TEE_Result res;
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

	if (algo != TEE_ALG_DSA_SHA1)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (*sig_len < 2 * mp_unsigned_bin_size(ltc_key.q)) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key.q);
		return TEE_ERROR_SHORT_BUFFER;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;
	ltc_res = dsa_sign_hash_raw(msg, msg_len, r, s, 0,
				    tee_ltc_get_rng_mpa(), &ltc_key);

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
	return res;
}

static TEE_Result dsa_verify(uint32_t algo, struct dsa_public_key *key,
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

	if (algo != TEE_ALG_DSA_SHA1)
		return TEE_ERROR_NOT_IMPLEMENTED;

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;
	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);
	ltc_res = dsa_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, &ltc_key);
	mp_clear_multi(r, s, NULL);

	if ((ltc_res == CRYPT_OK) && (ltc_stat == 1))
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_GENERIC;

	mp_clear_multi(r, s, NULL);
	return res;
}

/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

/* From libtomcrypt doc:
 *	Ciphertext stealing is a method of dealing with messages
 *	in CBC mode which are not a multiple of the block
 *	length.  This is accomplished by encrypting the last
 *	ciphertext block in ECB mode, and XOR'ing the output
 *	against the last partial block of plaintext. LibTomCrypt
 *	does not support this mode directly but it is fairly
 *	easy to emulate with a call to the cipher's
 *	ecb encrypt() callback function.
 *	The more sane way to deal with partial blocks is to pad
 *	them with zeroes, and then use CBC normally
 */

/*
 * From Global Platform: CTS = CBC-CS3
 */

struct tee_symmetric_cts {
	symmetric_ECB ecb;
	symmetric_CBC cbc;
};

#define XTS_TWEAK_SIZE 16
struct tee_symmetric_xts {
	symmetric_xts ctx;
	uint8_t tweak[XTS_TWEAK_SIZE];
};

static TEE_Result cipher_get_block_size(uint32_t algo, size_t *size)
{
	TEE_Result res;
	int ltc_cipherindex;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = cipher_descriptor[ltc_cipherindex].block_length;
	return TEE_SUCCESS;
}

static TEE_Result cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_AES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
	case TEE_ALG_AES_CTR:
		*size = sizeof(symmetric_CTR);
		break;
	case TEE_ALG_AES_CTS:
		*size = sizeof(struct tee_symmetric_cts);
		break;
	case TEE_ALG_AES_XTS:
		*size = sizeof(struct tee_symmetric_xts);
		break;
	case TEE_ALG_DES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_DES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
	case TEE_ALG_DES3_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_DES3_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static void get_des2_key(const uint8_t *key, size_t key_len,
			 uint8_t *key_intermediate,
			 uint8_t **real_key, size_t *real_key_len)
{
	if (key_len == 16) {
		/*
		 * This corresponds to a 2DES key. The 2DES encryption
		 * algorithm is similar to 3DES. Both perform and
		 * encryption step, then a decryption step, followed
		 * by another encryption step (EDE). However 2DES uses
		 * the same key for both of the encryption (E) steps.
		 */
		memcpy(key_intermediate, key, 16);
		memcpy(key_intermediate+16, key, 8);
		*real_key = key_intermediate;
		*real_key_len = 24;
	} else {
		*real_key = (uint8_t *)key;
		*real_key_len = key_len;
	}
}

static TEE_Result cipher_init(void *ctx, uint32_t algo, TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2, size_t key2_len,
			      const uint8_t *iv, size_t iv_len)
{
	TEE_Result res;
	int ltc_res, ltc_cipherindex;
	uint8_t *real_key, key_array[24];
	size_t real_key_len;
	struct tee_symmetric_cts *cts;
	struct tee_symmetric_xts *xts;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
		ltc_res = ecb_start(
			ltc_cipherindex, key1, key1_len,
			0, (symmetric_ECB *)ctx);
		break;

	case TEE_ALG_DES3_ECB_NOPAD:
		/* either des3 or des2, depending on the size of the key */
		get_des2_key(key1, key1_len, key_array,
			     &real_key, &real_key_len);
		ltc_res = ecb_start(
			ltc_cipherindex, real_key, real_key_len,
			0, (symmetric_ECB *)ctx);
		break;

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex].block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = cbc_start(
			ltc_cipherindex, iv, key1, key1_len,
			0, (symmetric_CBC *)ctx);
		break;

	case TEE_ALG_DES3_CBC_NOPAD:
		/* either des3 or des2, depending on the size of the key */
		get_des2_key(key1, key1_len, key_array,
			     &real_key, &real_key_len);
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex].block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = cbc_start(
			ltc_cipherindex, iv, real_key, real_key_len,
			0, (symmetric_CBC *)ctx);
		break;

	case TEE_ALG_AES_CTR:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex].block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = ctr_start(
			ltc_cipherindex, iv, key1, key1_len,
			0, CTR_COUNTER_BIG_ENDIAN, (symmetric_CTR *)ctx);
		break;

	case TEE_ALG_AES_CTS:
		cts = ctx;
		res = cipher_init((void *)(&(cts->ecb)),
					  TEE_ALG_AES_ECB_NOPAD, mode, key1,
					  key1_len, key2, key2_len, iv,
					  iv_len);
		if (res != TEE_SUCCESS)
			return res;
		res = cipher_init((void *)(&(cts->cbc)),
					  TEE_ALG_AES_CBC_NOPAD, mode, key1,
					  key1_len, key2, key2_len, iv,
					  iv_len);
		if (res != TEE_SUCCESS)
			return res;
		ltc_res = CRYPT_OK;
		break;

	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (key1_len != key2_len)
			return TEE_ERROR_BAD_PARAMETERS;
		if (iv) {
			if (iv_len != XTS_TWEAK_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			memcpy(xts->tweak, iv, iv_len);
		} else {
			memset(xts->tweak, 0, XTS_TWEAK_SIZE);
		}
		ltc_res = xts_start(
			ltc_cipherindex, key1, key2, key1_len,
			0, &xts->ctx);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				bool last_block, const uint8_t *data,
				size_t len, uint8_t *dst)
{
	int ltc_res = CRYPT_OK;
	struct tee_symmetric_cts *cts;
	struct tee_symmetric_xts *xts;


	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = ecb_encrypt(data, dst, len, ctx);
		else
			ltc_res = ecb_decrypt(data, dst, len, ctx);
		break;

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = cbc_encrypt(data, dst, len, ctx);
		else
			ltc_res = cbc_decrypt(data, dst, len, ctx);
		break;

	case TEE_ALG_AES_CTR:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = ctr_encrypt(data, dst, len, ctx);
		else
			ltc_res = ctr_decrypt(data, dst, len, ctx);
		break;

	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = xts_encrypt(data, len, dst, xts->tweak,
					      &xts->ctx);
		else
			ltc_res = xts_decrypt(data, len, dst, xts->tweak,
					      &xts->ctx);
		break;

	case TEE_ALG_AES_CTS:
		cts = ctx;
		return tee_aes_cbc_cts_update(&cts->cbc, &cts->ecb, mode,
					      last_block, data, len, dst);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static void cipher_final(void *ctx, uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		ecb_done(ctx);
		break;

	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		cbc_done(ctx);
		break;

	case TEE_ALG_AES_CTR:
		ctr_done(ctx);
		break;

	case TEE_ALG_AES_XTS:
		xts_done(&(((struct tee_symmetric_xts *)ctx)->ctx));
		break;

	case TEE_ALG_AES_CTS:
		cbc_done(&(((struct tee_symmetric_cts *)ctx)->cbc));
		ecb_done(&(((struct tee_symmetric_cts *)ctx)->ecb));
		break;

	default:
		/* TEE_ERROR_NOT_SUPPORTED; */
		break;
	}
}

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/

/*
 * CBC-MAC is not implemented in Libtomcrypt
 * This is implemented here as being the plain text which is encoded with IV=0.
 * Result of the CBC-MAC is the last 16-bytes cipher.
 */

#define CBCMAC_MAX_BLOCK_LEN 16
struct cbc_state {
	symmetric_CBC cbc;
	uint8_t block[CBCMAC_MAX_BLOCK_LEN];
	uint8_t digest[CBCMAC_MAX_BLOCK_LEN];
	size_t current_block_len, block_len;
	int is_computed;
};

static TEE_Result mac_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*size = sizeof(hmac_state);
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*size = sizeof(struct cbc_state);
		break;

	case TEE_ALG_AES_CMAC:
		*size = sizeof(omac_state);
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len)
{
	TEE_Result res;
	int ltc_hashindex, ltc_cipherindex;
	uint8_t iv[CBCMAC_MAX_BLOCK_LEN];
	struct cbc_state *cbc;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
		if (res != TEE_SUCCESS)
			return res;
		if (CRYPT_OK !=
		    hmac_init((hmac_state *)ctx, ltc_hashindex, key, len))
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
		if (res != TEE_SUCCESS)
			return res;

		cbc->block_len =
			cipher_descriptor[ltc_cipherindex].block_length;
		if (CBCMAC_MAX_BLOCK_LEN < cbc->block_len)
			return TEE_ERROR_BAD_PARAMETERS;
		memset(iv, 0, cbc->block_len);

		if (CRYPT_OK != cbc_start(
			ltc_cipherindex, iv, key, len, 0, &cbc->cbc))
				return TEE_ERROR_BAD_STATE;
		cbc->is_computed = 0;
		cbc->current_block_len = 0;
		break;

	case TEE_ALG_AES_CMAC:
		res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
		if (res != TEE_SUCCESS)
			return res;
		if (CRYPT_OK != omac_init((omac_state *)ctx, ltc_cipherindex,
					  key, len))
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result mac_update(void *ctx, uint32_t algo,
				     const uint8_t *data, size_t len)
{
	int ltc_res;
	struct cbc_state *cbc;
	size_t pad_len;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (CRYPT_OK != hmac_process((hmac_state *)ctx, data, len))
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = ctx;

		if ((cbc->current_block_len > 0) &&
		    (len + cbc->current_block_len >= cbc->block_len)) {
			pad_len = cbc->block_len - cbc->current_block_len;
			memcpy(cbc->block + cbc->current_block_len,
			       data, pad_len);
			data += pad_len;
			len -= pad_len;
			ltc_res = cbc_encrypt(cbc->block, cbc->digest,
					      cbc->block_len, &cbc->cbc);
			if (CRYPT_OK != ltc_res)
				return TEE_ERROR_BAD_STATE;
			cbc->is_computed = 1;
		}

		while (len >= cbc->block_len) {
			ltc_res = cbc_encrypt(data, cbc->digest,
					      cbc->block_len, &cbc->cbc);
			if (CRYPT_OK != ltc_res)
				return TEE_ERROR_BAD_STATE;
			cbc->is_computed = 1;
			data += cbc->block_len;
			len -= cbc->block_len;
		}

		if (len > 0)
			memcpy(cbc->block, data, len);
		cbc->current_block_len = len;
		break;

	case TEE_ALG_AES_CMAC:
		if (CRYPT_OK != omac_process((omac_state *)ctx, data, len))
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result mac_final(void *ctx, uint32_t algo, const uint8_t *data,
			    size_t data_len, uint8_t *digest,
			    size_t digest_len)
{
	struct cbc_state *cbc;
	size_t pad_len;
	unsigned long ltc_digest_len = digest_len;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (data && data_len) {
			if (CRYPT_OK != hmac_process((hmac_state *)ctx, data,
						     data_len))
				return TEE_ERROR_BAD_STATE;
		}
		if (CRYPT_OK != hmac_done((hmac_state *)ctx, digest,
					  &ltc_digest_len))
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		if (TEE_SUCCESS != mac_update(ctx, algo, data, data_len))
			return TEE_ERROR_BAD_STATE;

		/* Padding is required */
		switch (algo) {
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			/*
			 * Padding is in whole bytes. The value of each added
			 * byte is the number of bytes that are added, i.e. N
			 * bytes, each of value N are added
			 */
			pad_len = cbc->block_len - cbc->current_block_len;
			memset(cbc->block+cbc->current_block_len,
			       pad_len, pad_len);
			cbc->current_block_len = 0;
			if (TEE_SUCCESS != mac_update(
				ctx, algo, cbc->block, cbc->block_len))
					return TEE_ERROR_BAD_STATE;
			break;
		default:
			/* nothing to do */
			break;
		}

		if ((!cbc->is_computed) || (cbc->current_block_len != 0))
			return TEE_ERROR_BAD_STATE;

		memcpy(digest, cbc->digest, MIN(ltc_digest_len,
						cbc->block_len));
		cipher_final(&cbc->cbc, algo);
		break;

	case TEE_ALG_AES_CMAC:
		if (data && data_len) {
			if (CRYPT_OK != omac_process((omac_state *)ctx, data,
						     data_len))
				return TEE_ERROR_BAD_STATE;
		}
		if (CRYPT_OK != omac_done((omac_state *)ctx, digest,
					  &ltc_digest_len))
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

/******************************************************************************
 * Authenticated encryption
 ******************************************************************************/

#define TEE_CCM_KEY_MAX_LENGTH		32
#define TEE_CCM_NONCE_MAX_LENGTH	13
#define TEE_CCM_TAG_MAX_LENGTH		16
#define TEE_GCM_TAG_MAX_LENGTH		16
#define TEE_xCM_TAG_MAX_LENGTH		16

struct tee_ccm_state {
	ccm_state ctx;			/* the ccm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

struct tee_gcm_state {
	gcm_state ctx;			/* the gcm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

static TEE_Result authenc_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_CCM:
		*size = sizeof(struct tee_ccm_state);
		break;
	case TEE_ALG_AES_GCM:
		*size = sizeof(struct tee_gcm_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

static TEE_Result authenc_init(void *ctx, uint32_t algo,
			       TEE_OperationMode mode __unused,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	TEE_Result res;
	int ltc_res;
	int ltc_cipherindex;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;
	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* reset the state */
		ccm = ctx;
		memset(ccm, 0, sizeof(struct tee_ccm_state));
		ccm->tag_len = tag_len;

		/* Check the key length */
		if ((!key) || (key_len > TEE_CCM_KEY_MAX_LENGTH))
			return TEE_ERROR_BAD_PARAMETERS;

		/* check the nonce */
		if (nonce_len > TEE_CCM_NONCE_MAX_LENGTH)
			return TEE_ERROR_BAD_PARAMETERS;

		/* check the tag len */
		if ((tag_len < 4) ||
		    (tag_len > TEE_CCM_TAG_MAX_LENGTH) ||
		    (tag_len % 2 != 0))
			return TEE_ERROR_NOT_SUPPORTED;

		ltc_res = ccm_init(&ccm->ctx, ltc_cipherindex, key, key_len,
				   payload_len, tag_len, aad_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		/* Add the IV */
		ltc_res = ccm_add_nonce(&ccm->ctx, nonce, nonce_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* reset the state */
		gcm = ctx;
		memset(gcm, 0, sizeof(struct tee_gcm_state));
		gcm->tag_len = tag_len;

		ltc_res = gcm_init(&gcm->ctx, ltc_cipherindex, key, key_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		/* Add the IV */
		ltc_res = gcm_add_iv(&gcm->ctx, nonce, nonce_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_update_aad(void *ctx, uint32_t algo,
				     TEE_OperationMode mode __unused,
				     const uint8_t *data, size_t len)
{
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	int ltc_res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Add the AAD (note: aad can be NULL if aadlen == 0) */
		ccm = ctx;
		ltc_res = ccm_add_aad(&ccm->ctx, data, len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* Add the AAD (note: aad can be NULL if aadlen == 0) */
		gcm = ctx;
		ltc_res = gcm_add_aad(&gcm->ctx, data, len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_update_payload(void *ctx, uint32_t algo,
					 TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t src_len,
					 uint8_t *dst_data,
					 size_t *dst_len)
{
	TEE_Result res;
	int ltc_res, dir;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	unsigned char *pt, *ct;	/* the plain and the cipher text */

	if (mode == TEE_MODE_ENCRYPT) {
		pt = (unsigned char *)src_data;
		ct = dst_data;
	} else {
		pt = dst_data;
		ct = (unsigned char *)src_data;
	}

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = ctx;
		dir = (mode == TEE_MODE_ENCRYPT ? CCM_ENCRYPT : CCM_DECRYPT);
		ltc_res = ccm_process(&ccm->ctx, pt, src_len, ct, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		*dst_len = src_len;
		break;

	case TEE_ALG_AES_GCM:
		/* aad is optional ==> add one without length */
		gcm = ctx;
		if (gcm->ctx.mode == LTC_GCM_MODE_IV) {
			res = authenc_update_aad(gcm, algo, mode, 0, 0);
			if (res != TEE_SUCCESS)
				return res;
		}

		/* process the data */
		dir = (mode == TEE_MODE_ENCRYPT ? GCM_ENCRYPT : GCM_DECRYPT);
		ltc_res = gcm_process(&gcm->ctx, pt, src_len, ct, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		*dst_len = src_len;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_enc_final(void *ctx, uint32_t algo,
				    const uint8_t *src_data,
				    size_t src_len, uint8_t *dst_data,
				    size_t *dst_len, uint8_t *dst_tag,
				    size_t *dst_tag_len)
{
	TEE_Result res;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	size_t digest_size;
	int ltc_res;

	/* Check the resulting buffer is not too short */
	res = cipher_get_block_size(algo, &digest_size);
	if (res != TEE_SUCCESS)
		return res;

	/* Finalize the remaining buffer */
	res = authenc_update_payload(ctx, algo, TEE_MODE_ENCRYPT, src_data,
				     src_len, dst_data, dst_len);
	if (res != TEE_SUCCESS)
		return res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Check the tag length */
		ccm = ctx;
		if (*dst_tag_len < ccm->tag_len) {
			*dst_tag_len = ccm->tag_len;
			return TEE_ERROR_SHORT_BUFFER;
		}
		*dst_tag_len = ccm->tag_len;

		/* Compute the tag */
		ltc_res = ccm_done(&ccm->ctx, dst_tag,
				   (unsigned long *)dst_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* Check the tag length */
		gcm = ctx;
		if (*dst_tag_len < gcm->tag_len) {
			*dst_tag_len = gcm->tag_len;
			return TEE_ERROR_SHORT_BUFFER;
		}
		*dst_tag_len = gcm->tag_len;

		/* Compute the tag */
		ltc_res = gcm_done(&gcm->ctx, dst_tag,
				   (unsigned long *)dst_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_dec_final(void *ctx, uint32_t algo,
				    const uint8_t *src_data, size_t src_len,
				    uint8_t *dst_data, size_t *dst_len,
				    const uint8_t *tag, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;
	int ltc_res;
	uint8_t dst_tag[TEE_xCM_TAG_MAX_LENGTH];
	unsigned long ltc_tag_len = tag_len;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_xCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	/* Process the last buffer, if any */
	res = authenc_update_payload(ctx, algo, TEE_MODE_DECRYPT, src_data,
				     src_len, dst_data, dst_len);
	if (res != TEE_SUCCESS)
		return res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Finalize the authentication */
		ccm = ctx;
		ltc_res = ccm_done(&ccm->ctx, dst_tag, &ltc_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* Finalize the authentication */
		gcm = ctx;
		ltc_res = gcm_done(&gcm->ctx, dst_tag, &ltc_tag_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (buf_compare_ct(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;
	return res;
}

static void authenc_final(void *ctx, uint32_t algo)
{
	struct tee_ccm_state *ccm;
	struct tee_gcm_state *gcm;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = ctx;
		ccm_reset(&ccm->ctx);
		break;

	case TEE_ALG_AES_GCM:
		gcm = ctx;
		gcm_reset(&gcm->ctx);
		break;
	default:
		break;
	}
}

struct crypto_ops crypto_ops = {
	.name = "LibTomCrypt provider",
	.init = tee_ltc_init,
	.hash = {
		.get_ctx_size = hash_get_ctx_size,
		.init = hash_init,
		.update = hash_update,
		.final = hash_final,
	},
	.cipher = {
		.final = cipher_final,
		.get_block_size = cipher_get_block_size,
		.get_ctx_size = cipher_get_ctx_size,
		.init = cipher_init,
		.update = cipher_update,
	},
	.mac = {
		.get_ctx_size = mac_get_ctx_size,
		.init = mac_init,
		.update = mac_update,
		.final = mac_final,
	},
	.authenc = {
		.dec_final = authenc_dec_final,
		.enc_final = authenc_enc_final,
		.final = authenc_final,
		.get_ctx_size = authenc_get_ctx_size,
		.init = authenc_init,
		.update_aad = authenc_update_aad,
		.update_payload = authenc_update_payload,
	},
	.acipher = {
		.alloc_rsa_keypair = alloc_rsa_keypair,
		.alloc_rsa_public_key = alloc_rsa_public_key,
		.alloc_dsa_keypair = alloc_dsa_keypair,
		.alloc_dsa_public_key = alloc_dsa_public_key,
		.alloc_dh_keypair = alloc_dh_keypair,
		.dh_shared_secret = do_dh_shared_secret,
		.dsa_sign = dsa_sign,
		.dsa_verify = dsa_verify,
		.gen_dh_key = gen_dh_key,
		.gen_dsa_key = gen_dsa_key,
		.gen_rsa_key = gen_rsa_key,
		.rsaes_decrypt = rsaes_decrypt,
		.rsaes_encrypt = rsaes_encrypt,
		.rsanopad_decrypt = rsanopad_decrypt,
		.rsanopad_encrypt = rsanopad_encrypt,
		.rsassa_sign = rsassa_sign,
		.rsassa_verify = rsassa_verify,
	},
	.bignum = {
		.allocate = bn_allocate,
		.num_bytes = num_bytes,
		.bn2bin = bn2bin,
		.bin2bn = bin2bn,
		.copy = copy,
		.free = bn_free,
		.clear = bn_clear
	}
};
