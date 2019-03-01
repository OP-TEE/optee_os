// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <assert.h>
#include <crypto/aes-ccm.h>
#include <crypto/aes-gcm.h>
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


#if defined(_CFG_CRYPTO_WITH_HASH) || defined(CFG_CRYPTO_RSA) || \
	defined(CFG_CRYPTO_HMAC)

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
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_SHA1:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_HMAC_SHA1:
		*ltc_hashindex = find_hash("sha1");
		break;
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
		*ltc_hashindex = find_hash("md5");
		break;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_SHA224:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_HMAC_SHA224:
		*ltc_hashindex = find_hash("sha224");
		break;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_SHA256:
	case TEE_ALG_DSA_SHA256:
	case TEE_ALG_HMAC_SHA256:
		*ltc_hashindex = find_hash("sha256");
		break;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
		*ltc_hashindex = find_hash("sha384");
		break;
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
		*ltc_hashindex = find_hash("sha512");
		break;
#endif
	case TEE_ALG_RSASSA_PKCS1_V1_5:
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
#endif /* defined(_CFG_CRYPTO_WITH_HASH) ||
	  defined(_CFG_CRYPTO_WITH_ACIPHER) || defined(_CFG_CRYPTO_WITH_MAC) */

#if defined(_CFG_CRYPTO_WITH_CIPHER) || defined(_CFG_CRYPTO_WITH_MAC) || \
	defined(_CFG_CRYPTO_WITH_AUTHENC)
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
#if defined(CFG_CRYPTO_AES)
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
#endif
#if defined(CFG_CRYPTO_DES)
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
#endif
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (*ltc_cipherindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;
}
#endif /* defined(_CFG_CRYPTO_WITH_CIPHER) ||
	  defined(_CFG_CRYPTO_WITH_HASH) || defined(_CFG_CRYPTO_WITH_AUTHENC) */

/******************************************************************************
 * Message digest functions
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_HASH)

static TEE_Result hash_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
#endif
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
#endif
		*size = sizeof(hash_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_hash_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	res = hash_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_hash_free_ctx(void *ctx, uint32_t algo __unused)
{
	size_t ctx_size __maybe_unused;

	/*
	 * Check that it's a supported algo, or crypto_hash_alloc_ctx()
	 * could never have succeded above.
	 */
	if (ctx)
		assert(!hash_get_ctx_size(algo, &ctx_size));
	free(ctx);
}

void crypto_hash_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	TEE_Result res __maybe_unused;
	size_t ctx_size = 0;

	res = hash_get_ctx_size(algo, &ctx_size);
	assert(!res);
	memcpy(dst_ctx, src_ctx, ctx_size);
}

TEE_Result crypto_hash_init(void *ctx, uint32_t algo)
{
	int ltc_res;
	int ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex]->init(ctx) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result crypto_hash_update(void *ctx, uint32_t algo,
				      const uint8_t *data, size_t len)
{
	int ltc_res;
	int ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex]->process(ctx, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result crypto_hash_final(void *ctx, uint32_t algo, uint8_t *digest,
			     size_t len)
{
	int ltc_res;
	int ltc_hashindex;
	size_t hash_size;
	uint8_t block_digest[TEE_MAX_HASH_SIZE];
	uint8_t *tmp_digest;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_size = hash_descriptor[ltc_hashindex]->hashsize;

	if (hash_size > len) {
		if (hash_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;
		tmp_digest = block_digest; /* use a tempory buffer */
	} else {
		tmp_digest = digest;
	}
	if (hash_descriptor[ltc_hashindex]->done(ctx, tmp_digest) == CRYPT_OK) {
		if (hash_size > len)
			memcpy(digest, tmp_digest, len);
	} else {
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}
#endif /*_CFG_CRYPTO_WITH_HASH*/

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_ACIPHER)

static bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);

	return *s;
}

static TEE_Result __maybe_unused convert_ltc_verify_status(int ltc_res,
							   int ltc_stat)
{
	switch (ltc_res) {
	case CRYPT_OK:
		if (ltc_stat == 1)
			return TEE_SUCCESS;
		else
			return TEE_ERROR_SIGNATURE_INVALID;
	case CRYPT_INVALID_PACKET:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}

#if defined(CFG_CRYPTO_RSA)

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
					    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
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
	crypto_bignum_free(s->e);
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->n);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	crypto_bignum_free(s->qp);
	crypto_bignum_free(s->dp);

	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
					       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->e)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	if (!bn_alloc_max(&s->n))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->e);
	return TEE_ERROR_OUT_OF_MEMORY;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s)
{
	if (!s)
		return;
	crypto_bignum_free(s->n);
	crypto_bignum_free(s->e);
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result res;
	rsa_key ltc_tmp_key;
	int ltc_res;
	long e;

	/* get the public exponent */
	e = mp_get_int(key->e);

	/* Generate a temporary RSA key */
	ltc_res = rsa_make_key(NULL, find_prng("prng_mpa"), key_size / 8, e,
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
	blen = CFG_CORE_BIGNUM_MAX_BITS / sizeof(uint8_t);
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
		EMSG("rsa_exptmod() returned %d", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_exptmod() returned %d", ltc_res);
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

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	TEE_Result res;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PUBLIC;
	ltc_key.e = key->e;
	ltc_key.N = key->n;

	res = rsadorep(&ltc_key, src, src_len, dst, dst_len);
	return res;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	TEE_Result res;
	rsa_key ltc_key = { 0, };

	ltc_key.type = PK_PRIVATE;
	ltc_key.e = key->e;
	ltc_key.N = key->n;
	ltc_key.d = key->d;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	res = rsadorep(&ltc_key, src, src_len, dst, dst_len);
	return res;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
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
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		EMSG("tee_algo_to_ltc_hashindex() returned %d", (int)res);
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
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
	} else {
		/* Decoded message is always shorter than encrypted message */
		blen = src_len;
		ltc_rsa_algo = LTC_PKCS_1_OAEP;
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
		EMSG("rsa_decrypt_key_ex() returned %d", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d", ltc_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	if (ltc_stat != 1) {
		/* This will result in a panic */
		EMSG("rsa_decrypt_key_ex() returned %d and %d",
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

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
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
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS)
		goto out;

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5)
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
	else
		ltc_rsa_algo = LTC_PKCS_1_OAEP;

	ltc_res = rsa_encrypt_key_ex(src, src_len, dst,
				     (unsigned long *)(dst_len), label,
				     label_len, NULL, find_prng("prng_mpa"),
				     ltc_hashindex, ltc_rsa_algo, &ltc_key);
	switch (ltc_res) {
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_SIZE:
		EMSG("rsa_encrypt_key_ex() returned %d", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case CRYPT_OK:
		break;
	default:
		/* This will result in a panic */
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = TEE_SUCCESS;

out:
	return res;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
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
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		ltc_key.p = key->p;
		ltc_key.q = key->q;
		ltc_key.qP = key->qp;
		ltc_key.dP = key->dp;
		ltc_key.dQ = key->dq;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
		ltc_rsa_algo = LTC_PKCS_1_V1_5_NA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_PSS;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (ltc_rsa_algo != LTC_PKCS_1_V1_5_NA1) {
		ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
		if (ltc_res != CRYPT_OK) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					       &hash_size);
		if (res != TEE_SUCCESS)
			goto err;

		if (msg_len != hash_size) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}
	}

	mod_size = ltc_mp.unsigned_size((void *)(ltc_key.N));

	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_sig_len = mod_size;

	ltc_res = rsa_sign_hash_ex(msg, msg_len, sig, &ltc_sig_len,
				   ltc_rsa_algo, NULL, find_prng("prng_mpa"),
				   ltc_hashindex, salt_len, &ltc_key);

	*sig_len = ltc_sig_len;

	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	res = TEE_SUCCESS;

err:
	return res;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
{
	TEE_Result res;
	uint32_t bigint_size;
	size_t hash_size;
	int stat, ltc_hashindex, ltc_res, ltc_rsa_algo;
	rsa_key ltc_key = {
		.type = PK_PUBLIC,
		.e = key->e,
		.N = key->n
	};

	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
					       &hash_size);
		if (res != TEE_SUCCESS)
			goto err;

		if (msg_len != hash_size) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}
	}

	bigint_size = ltc_mp.unsigned_size(ltc_key.N);
	if (sig_len < bigint_size) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto err;
	}

	/* Get the algorithm */
	if (algo != TEE_ALG_RSASSA_PKCS1_V1_5) {
		res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
		if (res != TEE_SUCCESS)
			goto err;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
		ltc_rsa_algo = LTC_PKCS_1_V1_5_NA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_PSS;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	ltc_res = rsa_verify_hash_ex(sig, sig_len, msg, msg_len, ltc_rsa_algo,
				     ltc_hashindex, salt_len, &stat, &ltc_key);
	res = convert_ltc_verify_status(ltc_res, stat);
err:
	return res;
}

#endif /* CFG_CRYPTO_RSA */

#if defined(CFG_CRYPTO_DSA)

TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s,
					    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

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
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s,
					       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	if (!bn_alloc_max(&s->p))
		goto err;
	if (!bn_alloc_max(&s->q))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t key_size)
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
	ltc_res = dsa_make_key(NULL, find_prng("prng_mpa"), group_size,
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

TEE_Result crypto_acipher_dsa_sign(uint32_t algo, struct dsa_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size;
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

	if (algo != TEE_ALG_DSA_SHA1 &&
	    algo != TEE_ALG_DSA_SHA224 &&
	    algo != TEE_ALG_DSA_SHA256) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		goto err;
	if (mp_unsigned_bin_size(ltc_key.q) < hash_size)
		hash_size = mp_unsigned_bin_size(ltc_key.q);
	if (msg_len != hash_size) {
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	if (*sig_len < 2 * mp_unsigned_bin_size(ltc_key.q)) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key.q);
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ltc_res = dsa_sign_hash_raw(msg, msg_len, r, s, NULL,
				    find_prng("prng_mpa"), &ltc_key);

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

err:
	return res;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo, struct dsa_public_key *key,
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

	if (algo != TEE_ALG_DSA_SHA1 &&
	    algo != TEE_ALG_DSA_SHA224 &&
	    algo != TEE_ALG_DSA_SHA256) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);
	ltc_res = dsa_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, &ltc_key);
	mp_clear_multi(r, s, NULL);
	res = convert_ltc_verify_status(ltc_res, ltc_stat);
err:
	return res;
}

#endif /* CFG_CRYPTO_DSA */

#if defined(CFG_CRYPTO_DH)

TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s,
					   size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->g)) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

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
	ltc_res = dh_make_key(NULL, find_prng("prng_mpa"), q, xbits,
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

#endif /* CFG_CRYPTO_DH */

#if defined(CFG_CRYPTO_ECC)

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
					    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
					       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
}

/*
 * curve is part of TEE_ECC_CURVE_NIST_P192,...
 * algo is part of TEE_ALG_ECDSA_P192,..., and 0 if we do not have it
 */
static TEE_Result ecc_get_keysize(uint32_t curve, uint32_t algo,
				  size_t *key_size_bytes, size_t *key_size_bits)
{
	/*
	 * Excerpt of libtomcrypt documentation:
	 * ecc_make_key(... key_size ...): The keysize is the size of the
	 * modulus in bytes desired. Currently directly supported values
	 * are 12, 16, 20, 24, 28, 32, 48, and 65 bytes which correspond
	 * to key sizes of 112, 128, 160, 192, 224, 256, 384, and 521 bits
	 * respectively.
	 */

	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*key_size_bits = 192;
		*key_size_bytes = 24;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P192) &&
		    (algo != TEE_ALG_ECDH_P192))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		*key_size_bytes = 28;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P224) &&
		    (algo != TEE_ALG_ECDH_P224))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		*key_size_bytes = 32;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P256) &&
		    (algo != TEE_ALG_ECDH_P256))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		*key_size_bytes = 48;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P384) &&
		    (algo != TEE_ALG_ECDH_P384))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		/*
		 * set 66 instead of 65 wrt to Libtomcrypt documentation as
		 * if it the real key size
		 */
		*key_size_bytes = 66;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P521) &&
		    (algo != TEE_ALG_ECDH_P521))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		*key_size_bits = 0;
		*key_size_bytes = 0;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	TEE_Result res;
	ecc_key ltc_tmp_key;
	int ltc_res;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;

	res = ecc_get_keysize(key->curve, 0, &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS) {
		return res;
	}

	/* Generate the ECC key */
	ltc_res = ecc_make_key(NULL, find_prng("prng_mpa"),
			       key_size_bytes, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* check the size of the keys */
	if (((size_t)mp_count_bits(ltc_tmp_key.pubkey.x) > key_size_bits) ||
	    ((size_t)mp_count_bits(ltc_tmp_key.pubkey.y) > key_size_bits) ||
	    ((size_t)mp_count_bits(ltc_tmp_key.k) > key_size_bits)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* check LTC is returning z==1 */
	if (mp_count_bits(ltc_tmp_key.pubkey.z) != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Copy the key */
	ltc_mp.copy(ltc_tmp_key.k, key->d);
	ltc_mp.copy(ltc_tmp_key.pubkey.x, key->x);
	ltc_mp.copy(ltc_tmp_key.pubkey.y, key->y);

	res = TEE_SUCCESS;

exit:
	ecc_free(&ltc_tmp_key);		/* Free the temporary key */
	return res;
}

static TEE_Result ecc_compute_key_idx(ecc_key *ltc_key, size_t keysize)
{
	size_t x;

	for (x = 0; ((int)keysize > ltc_ecc_sets[x].size) &&
		    (ltc_ecc_sets[x].size != 0);
	     x++)
		;
	keysize = (size_t)ltc_ecc_sets[x].size;

	if ((keysize > ECC_MAXSIZE) || (ltc_ecc_sets[x].size == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_key->idx = -1;
	ltc_key->dp  = &ltc_ecc_sets[x];

	return TEE_SUCCESS;
}

/*
 * Given a keypair "key", populate the Libtomcrypt private key "ltc_key"
 * It also returns the key size, in bytes
 */
static TEE_Result ecc_populate_ltc_private_key(ecc_key *ltc_key,
					       struct ecc_keypair *key,
					       uint32_t algo,
					       size_t *key_size_bytes)
{
	TEE_Result res;
	size_t key_size_bits;

	memset(ltc_key, 0, sizeof(*ltc_key));
	ltc_key->type = PK_PRIVATE;
	ltc_key->k = key->d;

	/* compute the index of the ecc curve */
	res = ecc_get_keysize(key->curve, algo,
			      key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	return ecc_compute_key_idx(ltc_key, *key_size_bytes);
}

/*
 * Given a public "key", populate the Libtomcrypt public key "ltc_key"
 * It also returns the key size, in bytes
 */
static TEE_Result ecc_populate_ltc_public_key(ecc_key *ltc_key,
					      struct ecc_public_key *key,
					      void *key_z,
					      uint32_t algo,
					      size_t *key_size_bytes)
{
	TEE_Result res;
	size_t key_size_bits;
	uint8_t one[1] = { 1 };


	memset(ltc_key, 0, sizeof(*ltc_key));
	ltc_key->type = PK_PUBLIC;
	ltc_key->pubkey.x = key->x;
	ltc_key->pubkey.y = key->y;
	ltc_key->pubkey.z = key_z;
	mp_read_unsigned_bin(ltc_key->pubkey.z, one, sizeof(one));

	/* compute the index of the ecc curve */
	res = ecc_get_keysize(key->curve, algo,
			      key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	return ecc_compute_key_idx(ltc_key, *key_size_bytes);
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	int ltc_res;
	void *r, *s;
	size_t key_size_bytes;
	ecc_key ltc_key;

	if (algo == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = ecc_populate_ltc_private_key(&ltc_key, key, algo,
					   &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto err;

	if (*sig_len < 2 * key_size_bytes) {
		*sig_len = 2 * key_size_bytes;
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ltc_res = ecc_sign_hash_raw(msg, msg_len, r, s,
				    NULL, find_prng("prng_mpa"), &ltc_key);

	if (ltc_res == CRYPT_OK) {
		*sig_len = 2 * key_size_bytes;
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

err:
	return res;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	int ltc_stat;
	int ltc_res;
	void *r;
	void *s;
	void *key_z;
	size_t key_size_bytes;
	ecc_key ltc_key;

	if (algo == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = mp_init_multi(&key_z, &r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = ecc_populate_ltc_public_key(&ltc_key, key, key_z, algo,
					  &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;

	/* check keysize vs sig_len */
	if ((key_size_bytes * 2) != sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);

	ltc_res = ecc_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, &ltc_key);
	res = convert_ltc_verify_status(ltc_res, ltc_stat);
out:
	mp_clear_multi(key_z, r, s, NULL);
	return res;
}

TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	TEE_Result res;
	int ltc_res;
	ecc_key ltc_private_key;
	ecc_key ltc_public_key;
	size_t key_size_bytes;
	void *key_z;

	/* Check the curves are the same */
	if (private_key->curve != public_key->curve) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = mp_init_multi(&key_z, NULL);
	if (ltc_res != CRYPT_OK) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = ecc_populate_ltc_private_key(&ltc_private_key, private_key,
					   0, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;
	res = ecc_populate_ltc_public_key(&ltc_public_key, public_key, key_z,
					  0, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;

	ltc_res = ecc_shared_secret(&ltc_private_key, &ltc_public_key,
				    secret, secret_len);
	if (ltc_res == CRYPT_OK)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_BAD_PARAMETERS;

out:
	mp_clear_multi(key_z, NULL);
	return res;
}
#endif /* CFG_CRYPTO_ECC */

#endif /* _CFG_CRYPTO_WITH_ACIPHER */

/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_CIPHER)
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

#if defined(CFG_CRYPTO_CTS)
struct tee_symmetric_cts {
	symmetric_ECB ecb;
	symmetric_CBC cbc;
};
#endif

#if defined(CFG_CRYPTO_XTS)
#define XTS_TWEAK_SIZE 16
struct tee_symmetric_xts {
	symmetric_xts ctx;
	uint8_t tweak[XTS_TWEAK_SIZE];
};
#endif

static TEE_Result cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		*size = sizeof(symmetric_CTR);
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		*size = sizeof(struct tee_symmetric_cts);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		*size = sizeof(struct tee_symmetric_xts);
		break;
#endif
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
	case TEE_ALG_DES3_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
	case TEE_ALG_DES3_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
#endif
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_cipher_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	res = cipher_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_cipher_free_ctx(void *ctx, uint32_t algo __maybe_unused)
{
	size_t ctx_size __maybe_unused;

	/*
	 * Check that it's a supported algo, or crypto_cipher_alloc_ctx()
	 * could never have succeded above.
	 */
	if (ctx)
		assert(!cipher_get_ctx_size(algo, &ctx_size));
	free(ctx);
}

void crypto_cipher_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	TEE_Result res __maybe_unused;
	size_t ctx_size = 0;

	res = cipher_get_ctx_size(algo, &ctx_size);
	assert(!res);
	memcpy(dst_ctx, src_ctx, ctx_size);
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

TEE_Result crypto_cipher_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode __maybe_unused,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2 __maybe_unused,
			      size_t key2_len __maybe_unused,
			      const uint8_t *iv __maybe_unused,
			      size_t iv_len __maybe_unused)
{
	TEE_Result res;
	int ltc_res, ltc_cipherindex;
	uint8_t *real_key, key_array[24];
	size_t real_key_len;
#if defined(CFG_CRYPTO_CTS)
	struct tee_symmetric_cts *cts;
#endif
#if defined(CFG_CRYPTO_XTS)
	struct tee_symmetric_xts *xts;
#endif

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
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
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex]->block_length)
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
		    (size_t)cipher_descriptor[ltc_cipherindex]->block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = cbc_start(
			ltc_cipherindex, iv, real_key, real_key_len,
			0, (symmetric_CBC *)ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex]->block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = ctr_start(
			ltc_cipherindex, iv, key1, key1_len,
			0, CTR_COUNTER_BIG_ENDIAN, (symmetric_CTR *)ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		cts = ctx;
		res = crypto_cipher_init((void *)(&(cts->ecb)),
					 TEE_ALG_AES_ECB_NOPAD, mode, key1,
					 key1_len, key2, key2_len, iv, iv_len);
		if (res != TEE_SUCCESS)
			return res;
		res = crypto_cipher_init((void *)(&(cts->cbc)),
					 TEE_ALG_AES_CBC_NOPAD, mode, key1,
					 key1_len, key2, key2_len, iv, iv_len);
		if (res != TEE_SUCCESS)
			return res;
		ltc_res = CRYPT_OK;
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
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
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result crypto_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				bool last_block __maybe_unused,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	int ltc_res = CRYPT_OK;
#if defined(CFG_CRYPTO_CTS)
	struct tee_symmetric_cts *cts;
#endif
#if defined(CFG_CRYPTO_XTS)
	struct tee_symmetric_xts *xts;
#endif

	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = ecb_encrypt(data, dst, len, ctx);
		else
			ltc_res = ecb_decrypt(data, dst, len, ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = cbc_encrypt(data, dst, len, ctx);
		else
			ltc_res = cbc_decrypt(data, dst, len, ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = ctr_encrypt(data, dst, len, ctx);
		else
			ltc_res = ctr_decrypt(data, dst, len, ctx);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = xts_encrypt(data, len, dst, xts->tweak,
					      &xts->ctx);
		else
			ltc_res = xts_decrypt(data, len, dst, xts->tweak,
					      &xts->ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		cts = ctx;
		return tee_aes_cbc_cts_update(&cts->cbc, &cts->ecb, mode,
					      last_block, data, len, dst);
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

void crypto_cipher_final(void *ctx, uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		ecb_done(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc_done(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		ctr_done(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		xts_done(&(((struct tee_symmetric_xts *)ctx)->ctx));
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		cbc_done(&(((struct tee_symmetric_cts *)ctx)->cbc));
		ecb_done(&(((struct tee_symmetric_cts *)ctx)->ecb));
		break;
#endif
	default:
		assert(!"Unhandled algo");
		break;
	}
}
#endif /* _CFG_CRYPTO_WITH_CIPHER */

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/

#if defined(_CFG_CRYPTO_WITH_MAC)

#if defined(CFG_CRYPTO_CBC_MAC)
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
#endif

static TEE_Result mac_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*size = sizeof(hmac_state);
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*size = sizeof(struct cbc_state);
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		*size = sizeof(omac_state);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_mac_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	res = mac_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_mac_free_ctx(void *ctx, uint32_t algo __maybe_unused)
{
	size_t ctx_size __maybe_unused;

	/*
	 * Check that it's a supported algo, or crypto_mac_alloc_ctx()
	 * could never have succeded above.
	 */
	if (ctx)
		assert(!mac_get_ctx_size(algo, &ctx_size));
	free(ctx);
}

void crypto_mac_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	TEE_Result res __maybe_unused;
	size_t ctx_size = 0;

	res = mac_get_ctx_size(algo, &ctx_size);
	assert(!res);
	memcpy(dst_ctx, src_ctx, ctx_size);
}

TEE_Result crypto_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len)
{
	TEE_Result res;
#if defined(CFG_CRYPTO_HMAC)
	int ltc_hashindex;
#endif
#if defined(CFG_CRYPTO_CBC_MAC) || defined(CFG_CRYPTO_CMAC)
	int ltc_cipherindex;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	uint8_t *real_key;
	uint8_t key_array[24];
	size_t real_key_len;
	uint8_t iv[CBCMAC_MAX_BLOCK_LEN];
	struct cbc_state *cbc;
#endif

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
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
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
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
			cipher_descriptor[ltc_cipherindex]->block_length;
		if (CBCMAC_MAX_BLOCK_LEN < cbc->block_len)
			return TEE_ERROR_BAD_PARAMETERS;
		memset(iv, 0, cbc->block_len);

		if (algo == TEE_ALG_DES3_CBC_MAC_NOPAD ||
		    algo == TEE_ALG_DES3_CBC_MAC_PKCS5) {
			get_des2_key(key, len, key_array,
				     &real_key, &real_key_len);
			key = real_key;
			len = real_key_len;
		}
		if (CRYPT_OK != cbc_start(
			ltc_cipherindex, iv, key, len, 0, &cbc->cbc))
				return TEE_ERROR_BAD_STATE;
		cbc->is_computed = 0;
		cbc->current_block_len = 0;
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
		if (res != TEE_SUCCESS)
			return res;
		if (CRYPT_OK != omac_init((omac_state *)ctx, ltc_cipherindex,
					  key, len))
			return TEE_ERROR_BAD_STATE;
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t len)
{
#if defined(CFG_CRYPTO_CBC_MAC)
	int ltc_res;
	struct cbc_state *cbc;
	size_t pad_len;
#endif

	if (!data || !len)
		return TEE_SUCCESS;

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (CRYPT_OK != hmac_process((hmac_state *)ctx, data, len))
			return TEE_ERROR_BAD_STATE;
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
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
			cbc->current_block_len = 0;
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

		if (len > 0) {
			assert(cbc->current_block_len + len < cbc->block_len);
			memcpy(cbc->block + cbc->current_block_len, data, len);
			cbc->current_block_len += len;
		}
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		if (CRYPT_OK != omac_process((omac_state *)ctx, data, len))
			return TEE_ERROR_BAD_STATE;
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_mac_final(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t digest_len)
{
#if defined(CFG_CRYPTO_CBC_MAC)
	struct cbc_state *cbc;
	size_t pad_len;
#endif
	unsigned long ltc_digest_len = digest_len;

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (CRYPT_OK != hmac_done((hmac_state *)ctx, digest,
					  &ltc_digest_len))
			return TEE_ERROR_BAD_STATE;
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

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
			if (TEE_SUCCESS != crypto_mac_update(ctx, algo,
							     cbc->block,
							     cbc->block_len))
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
		crypto_cipher_final(&cbc->cbc, algo);
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		if (CRYPT_OK != omac_done((omac_state *)ctx, digest,
					  &ltc_digest_len))
			return TEE_ERROR_BAD_STATE;
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}
#endif /* _CFG_CRYPTO_WITH_MAC */

/******************************************************************************
 * Authenticated encryption
 ******************************************************************************/

#define TEE_CCM_KEY_MAX_LENGTH		32
#define TEE_CCM_NONCE_MAX_LENGTH	13
#define TEE_CCM_TAG_MAX_LENGTH		16
#define TEE_GCM_TAG_MAX_LENGTH		16

#if defined(CFG_CRYPTO_CCM)
struct tee_ccm_state {
	ccm_state ctx;			/* the ccm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

TEE_Result crypto_aes_ccm_alloc_ctx(void **ctx_ret)
{
	struct tee_ccm_state *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_aes_ccm_free_ctx(void *ctx)
{
	free(ctx);
}

void crypto_aes_ccm_copy_state(void *dst_ctx, void *src_ctx)
{
	memcpy(dst_ctx, src_ctx, sizeof(struct tee_ccm_state));
}

TEE_Result crypto_aes_ccm_init(void *ctx, TEE_OperationMode mode __unused,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	TEE_Result res;
	int ltc_res;
	int ltc_cipherindex;
	struct tee_ccm_state *ccm = ctx;

	res = tee_algo_to_ltc_cipherindex(TEE_ALG_AES_CCM, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	/* reset the state */
	memset(ccm, 0, sizeof(struct tee_ccm_state));
	ccm->tag_len = tag_len;

	/* Check the key length */
	if ((!key) || (key_len > TEE_CCM_KEY_MAX_LENGTH))
		return TEE_ERROR_BAD_PARAMETERS;

	/* check the nonce */
	if (nonce_len > TEE_CCM_NONCE_MAX_LENGTH)
		return TEE_ERROR_BAD_PARAMETERS;

	/* check the tag len */
	if ((tag_len < 4) || (tag_len > TEE_CCM_TAG_MAX_LENGTH) ||
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

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_update_aad(void *ctx, const uint8_t *data, size_t len)
{
	struct tee_ccm_state *ccm = ctx;
	int ltc_res;

	/* Add the AAD (note: aad can be NULL if aadlen == 0) */
	ltc_res = ccm_add_aad(&ccm->ctx, data, len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t len, uint8_t *dst_data)
{
	int ltc_res, dir;
	struct tee_ccm_state *ccm = ctx;
	unsigned char *pt, *ct;	/* the plain and the cipher text */

	if (mode == TEE_MODE_ENCRYPT) {
		pt = (unsigned char *)src_data;
		ct = dst_data;
		dir = CCM_ENCRYPT;
	} else {
		pt = dst_data;
		ct = (unsigned char *)src_data;
		dir = CCM_DECRYPT;
	}
	ltc_res = ccm_process(&ccm->ctx, pt, len, ct, dir);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_enc_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    uint8_t *dst_tag, size_t *dst_tag_len)
{
	TEE_Result res;
	struct tee_ccm_state *ccm = ctx;
	int ltc_res;

	/* Finalize the remaining buffer */
	res = crypto_aes_ccm_update_payload(ctx, TEE_MODE_ENCRYPT, src_data,
					    len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Check the tag length */
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

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_dec_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    const uint8_t *tag, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct tee_ccm_state *ccm = ctx;
	int ltc_res;
	uint8_t dst_tag[TEE_CCM_TAG_MAX_LENGTH];
	unsigned long ltc_tag_len = tag_len;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_CCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	/* Process the last buffer, if any */
	res = crypto_aes_ccm_update_payload(ctx, TEE_MODE_DECRYPT, src_data,
					    len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Finalize the authentication */
	ltc_res = ccm_done(&ccm->ctx, dst_tag, &ltc_tag_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	if (buf_compare_ct(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;
	return res;
}

void crypto_aes_ccm_final(void *ctx)
{
	struct tee_ccm_state *ccm = ctx;

	ccm_reset(&ccm->ctx);
}
#endif /*CFG_CRYPTO_CCM*/

#if defined(CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB)
struct tee_gcm_state {
	gcm_state ctx;			/* the gcm state as defined by LTC */
	size_t tag_len;			/* tag length */
};

TEE_Result crypto_aes_gcm_alloc_ctx(void **ctx_ret)
{
	struct tee_gcm_state *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_aes_gcm_free_ctx(void *ctx)
{
	free(ctx);
}

void crypto_aes_gcm_copy_state(void *dst_ctx, void *src_ctx)
{
	memcpy(dst_ctx, src_ctx, sizeof(struct tee_gcm_state));
}

TEE_Result crypto_aes_gcm_init(void *ctx, TEE_OperationMode mode __unused,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len)
{
	TEE_Result res;
	int ltc_res;
	int ltc_cipherindex;
	struct tee_gcm_state *gcm = ctx;

	res = tee_algo_to_ltc_cipherindex(TEE_ALG_AES_GCM, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	/* reset the state */
	memset(gcm, 0, sizeof(struct tee_gcm_state));
	gcm->tag_len = tag_len;

	ltc_res = gcm_init(&gcm->ctx, ltc_cipherindex, key, key_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	/* Add the IV */
	ltc_res = gcm_add_iv(&gcm->ctx, nonce, nonce_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_gcm_update_aad(void *ctx, const uint8_t *data, size_t len)
{
	struct tee_gcm_state *gcm = ctx;
	int ltc_res;

	/* Add the AAD (note: aad can be NULL if aadlen == 0) */
	ltc_res = gcm_add_aad(&gcm->ctx, data, len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_gcm_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t len, uint8_t *dst_data)
{
	TEE_Result res;
	int ltc_res, dir;
	struct tee_gcm_state *gcm = ctx;
	unsigned char *pt, *ct;	/* the plain and the cipher text */

	if (mode == TEE_MODE_ENCRYPT) {
		pt = (unsigned char *)src_data;
		ct = dst_data;
		dir = GCM_ENCRYPT;
	} else {
		pt = dst_data;
		ct = (unsigned char *)src_data;
		dir = GCM_DECRYPT;
	}

	/* aad is optional ==> add one without length */
	if (gcm->ctx.mode == LTC_GCM_MODE_IV) {
		res = crypto_aes_gcm_update_aad(gcm, NULL, 0);
		if (res != TEE_SUCCESS)
			return res;
	}

	/* process the data */
	ltc_res = gcm_process(&gcm->ctx, pt, len, ct, dir);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_gcm_enc_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    uint8_t *dst_tag, size_t *dst_tag_len)
{
	TEE_Result res;
	struct tee_gcm_state *gcm = ctx;
	int ltc_res;

	/* Finalize the remaining buffer */
	res = crypto_aes_gcm_update_payload(ctx, TEE_MODE_ENCRYPT, src_data,
					    len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Check the tag length */
	if (*dst_tag_len < gcm->tag_len) {
		*dst_tag_len = gcm->tag_len;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_tag_len = gcm->tag_len;

	/* Compute the tag */
	ltc_res = gcm_done(&gcm->ctx, dst_tag, (unsigned long *)dst_tag_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_gcm_dec_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    const uint8_t *tag, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct tee_gcm_state *gcm = ctx;
	int ltc_res;
	uint8_t dst_tag[TEE_GCM_TAG_MAX_LENGTH];
	unsigned long ltc_tag_len = tag_len;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_GCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	/* Process the last buffer, if any */
	res = crypto_aes_gcm_update_payload(ctx, TEE_MODE_DECRYPT, src_data,
					    len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Finalize the authentication */
	ltc_res = gcm_done(&gcm->ctx, dst_tag, &ltc_tag_len);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_STATE;

	if (buf_compare_ct(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;
	return res;
}

void crypto_aes_gcm_final(void *ctx)
{
	struct tee_gcm_state *gcm = ctx;

	gcm_reset(&gcm->ctx);
}
#endif /*CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB*/

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
	if (buf_compare_ct(digest, hash, sizeof(digest)) != 0)
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
				     void *enc_key, unsigned int *rounds)
{
	symmetric_key skey;

	if (aes_setup(key, key_len, 0, &skey))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(enc_key, skey.rijndael.eK, sizeof(skey.rijndael.eK));
	*rounds = skey.rijndael.Nr;
	return TEE_SUCCESS;
}

void crypto_aes_enc_block(const void *enc_key, unsigned int rounds,
			  const void *src, void *dst)
{
	symmetric_key skey;

	memcpy(skey.rijndael.eK, enc_key, sizeof(skey.rijndael.eK));
	skey.rijndael.Nr = rounds;
	if (aes_ecb_encrypt(src, dst, &skey))
		panic();
}
