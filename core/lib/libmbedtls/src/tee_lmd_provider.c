/*
 * Copyright (C) 2017, ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <crypto/aes-ccm.h>
#include <crypto/aes-gcm.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include "mbedtls.h"
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

#if defined(_CFG_CRYPTO_WITH_HASH) || defined(CFG_CRYPTO_RSA) || \
	defined(CFG_CRYPTO_HMAC)
/*
 * Get mbedtls hash info given a TEE Algorithm "algo"
 * Return
 * - mbedtls_md_info_t * in case of success,
 * - NULL in case of error
 */
static const mbedtls_md_info_t *tee_algo_to_mbedtls_hash_info(uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_SHA1:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_HMAC_SHA1:
		return mbedtls_md_info_from_string("SHA1");
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
		return mbedtls_md_info_from_string("MD5");
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_SHA224:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_HMAC_SHA224:
		return mbedtls_md_info_from_string("SHA224");
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_SHA256:
	case TEE_ALG_DSA_SHA256:
	case TEE_ALG_HMAC_SHA256:
		return mbedtls_md_info_from_string("SHA256");
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
		return mbedtls_md_info_from_string("SHA384");
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
		return mbedtls_md_info_from_string("SHA512");
#endif
	case TEE_ALG_RSAES_PKCS1_V1_5:
		/* invalid one. but it should not be used anyway */
		return NULL;

	default:
		return NULL;
	}
}

static uint32_t tee_algo_to_mbedtls_hash_algo(uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_SHA1:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_HMAC_SHA1:
		return MBEDTLS_MD_SHA1;
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
		return MBEDTLS_MD_MD5;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_SHA224:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_HMAC_SHA224:
		return MBEDTLS_MD_SHA224;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_SHA256:
	case TEE_ALG_DSA_SHA256:
	case TEE_ALG_HMAC_SHA256:
		return MBEDTLS_MD_SHA256;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
		return MBEDTLS_MD_SHA384;
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
		return MBEDTLS_MD_SHA512;
#endif
	default:
		return MBEDTLS_MD_NONE;
	}
}
#endif /*
	* defined(_CFG_CRYPTO_WITH_HASH) ||
	* defined(CFG_CRYPTO_RSA) || defined(_CFG_CRYPTO_WITH_MAC)
	*/

/******************************************************************************
 * Message digest functions
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_HASH)

TEE_Result crypto_hash_get_ctx_size(uint32_t algo, size_t *size)
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
		*size = sizeof(mbedtls_md_context_t);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_hash_init(void *ctx, uint32_t algo)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res;
	const mbedtls_md_info_t *md_info = NULL;

	if (ctx == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	md_info = tee_algo_to_mbedtls_hash_info(algo);
	if (md_info == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	mbedtls_md_init(ctx);

	lmd_res = mbedtls_md_setup(ctx, md_info, 0);
	if (lmd_res != 0) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	lmd_res = mbedtls_md_starts(ctx);
	if (lmd_res != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	return res;
err:
	mbedtls_md_free(ctx);

	return res;
}

TEE_Result crypto_hash_update(void *ctx, uint32_t algo,
				      const uint8_t *data, size_t len)
{
	int lmd_res;

	if (ctx == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	lmd_res = mbedtls_md_update(ctx, data, len);
	if (lmd_res != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

TEE_Result crypto_hash_final(void *ctx, uint32_t algo, uint8_t *digest,
			     size_t len)
{
	size_t hash_size;
	uint8_t block_digest[TEE_MAX_HASH_SIZE];
	uint8_t *tmp_digest;

	if (ctx == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_size = ((mbedtls_md_context_t *)ctx)->md_info->size;

	if (hash_size > len) {
		if (hash_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;
		tmp_digest = block_digest; /* use a tempory buffer */
	} else {
		tmp_digest = digest;
	}

	mbedtls_md_finish(ctx, tmp_digest);

	if (hash_size > len)
		memcpy(digest, tmp_digest, len);

	return TEE_SUCCESS;
}
#endif /*_CFG_CRYPTO_WITH_HASH*/

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#define ciL		(sizeof(mbedtls_mpi_uint))	/* chars in limb  */
#define biL		(ciL << 3)			/* bits  in limb  */
#define biH		(ciL << 2)			/* half limb size */
#define BITS_TO_LIMBS(i)		((i) / biL + ((i) % biL != 0))

#define LMD_MAX_BITS_PER_VARIABLE	(4096)

size_t crypto_bignum_num_bytes(struct bignum *a)
{
	assert(a != NULL);
	return mbedtls_mpi_size((const mbedtls_mpi *)a);
}

size_t crypto_bignum_num_bits(struct bignum *a)
{
	assert(a != NULL);
	return mbedtls_mpi_bitlen((const mbedtls_mpi *)a);
}

int32_t crypto_bignum_compare(struct bignum *a, struct bignum *b)
{
	int ret;

	assert(a != NULL);
	assert(b != NULL);
	ret = mbedtls_mpi_cmp_mpi((const mbedtls_mpi *)a,
		(const mbedtls_mpi *)b);
	if (ret < 0)
		return -1;
	else if (ret > 0)
		return 1;
	else
		return 0;
}

void crypto_bignum_bn2bin(const struct bignum *from, uint8_t *to)
{
	size_t len;

	assert(from != NULL);
	assert(to != NULL);
	len = crypto_bignum_num_bytes((struct bignum *)from);
	mbedtls_mpi_write_binary((mbedtls_mpi *)from, to, len);
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from, size_t fromsize,
			 struct bignum *to)
{
	assert(from != NULL);
	assert(to != NULL);
	if (mbedtls_mpi_read_binary((mbedtls_mpi *)to, from, fromsize) != 0)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

void crypto_bignum_copy(struct bignum *to, const struct bignum *from)
{
	assert(from != NULL);
	assert(to != NULL);
	mbedtls_mpi_copy((mbedtls_mpi *)to, (const mbedtls_mpi *)from);
}

struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	mbedtls_mpi *bn;

	bn = calloc(1, sizeof(mbedtls_mpi));
	if (bn == NULL)
		return NULL;
	mbedtls_mpi_init(bn);
	if (mbedtls_mpi_grow(bn, BITS_TO_LIMBS(size_bits)) != 0)
		return NULL;

	return (struct bignum *)bn;
}

void crypto_bignum_free(struct bignum *s)
{
	mbedtls_mpi_free((mbedtls_mpi *)s);
	free(s);
}

void crypto_bignum_clear(struct bignum *s)
{
	volatile mbedtls_mpi_uint *p = ((mbedtls_mpi *)s)->p;
	size_t n = ((mbedtls_mpi *)s)->n;

	while (n--)
		*p++ = 0;
}

static bool bn_alloc_max(struct bignum **s)
{
	*s = crypto_bignum_allocate(LMD_MAX_BITS_PER_VARIABLE);
	return !!(*s);
}

static unsigned long int next = 1;

/* Return next random integer */

static int _rand(void)
{
	next = next * 1103515245L + 12345;
	return (unsigned int) (next / 65536L) % 32768L;
}

static int mbd_rand(void *rng_state, unsigned char *output, size_t len)
{
	size_t use_len;
	int rnd;

	if (rng_state != NULL)
		rng_state  = NULL;

	while (len > 0) {
		use_len = len;
		if (use_len > sizeof(int))
			use_len = sizeof(int);

		rnd = _rand();
		memcpy(output, &rnd, use_len);
		output += use_len;
		len -= use_len;
	}
	return 0;
}

#if defined(CFG_CRYPTO_RSA)

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->e = crypto_bignum_allocate(key_size_bits);
	if (!(s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	s->d = crypto_bignum_allocate(key_size_bits);
	if (!(s->d))
		goto err;
	s->n = crypto_bignum_allocate(key_size_bits);
	if (!(s->n))
		goto err;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!(s->p))
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!(s->q))
		goto err;
	s->qp = crypto_bignum_allocate(key_size_bits);
	if (!(s->qp))
		goto err;
	s->dp = crypto_bignum_allocate(key_size_bits);
	if (!(s->dp))
		goto err;
	s->dq = crypto_bignum_allocate(key_size_bits);
	if (!(s->dq))
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
					       size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->e = crypto_bignum_allocate(key_size_bits);
	if (!(s->e))
		return TEE_ERROR_OUT_OF_MEMORY;
	s->n = crypto_bignum_allocate(key_size_bits);
	if (!(s->n))
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
	mbedtls_rsa_context rsa;
	mbedtls_ctr_drbg_context ctr_drbg;
	int lmd_res;
	uint32_t e;

	mbedtls_rsa_init(&rsa, 0, 0);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	lmd_res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbd_rand, NULL, NULL, 0);
	if (lmd_res != 0) {
		EMSG(" failed\n  ! mbedtls_ctr_drbg_seed ret is 0x%x\n",
			-lmd_res);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		return TEE_ERROR_SECURITY;
	}

	/* get the public exponent */
	mbedtls_mpi_write_binary((mbedtls_mpi *)key->e,
				(unsigned char *)&e, sizeof(uint32_t));

	e = TEE_U32_FROM_BIG_ENDIAN(e);
	lmd_res = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random,
				      &ctr_drbg, key_size, (int)e);
	if (lmd_res != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mbedtls_mpi_bitlen(&rsa.N) != key_size) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* Copy the key */
		crypto_bignum_copy(key->e, (void *)&rsa.E);
		crypto_bignum_copy(key->d, (void *)&rsa.D);
		crypto_bignum_copy(key->n, (void *)&rsa.N);
		crypto_bignum_copy(key->p, (void *)&rsa.P);

		crypto_bignum_copy(key->q, (void *)&rsa.Q);
		crypto_bignum_copy(key->qp, (void *)&rsa.QP);
		crypto_bignum_copy(key->dp, (void *)&rsa.DP);
		crypto_bignum_copy(key->dq, (void *)&rsa.DQ);

		res = TEE_SUCCESS;
	}
	/* Free the temporary key */
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_rsa_free(&rsa);

	return res;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_rsa_context rsa;
	int lmd_res;
	uint8_t *buf = NULL;
	unsigned long blen, offset;

	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.N = *(mbedtls_mpi *)key->n;

	rsa.len = crypto_bignum_num_bytes((void *)&rsa.N);

	blen = LMD_MAX_BITS_PER_VARIABLE / 8;
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(buf, 0, blen);
	memcpy(buf + rsa.len - src_len, src, src_len);

	lmd_res = mbedtls_rsa_public(&rsa, buf, buf);
	switch (lmd_res) {
	case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
		EMSG("mbedtls_rsa_public() returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case 0:
		break;
	default:
		/* This will result in a panic */
		EMSG("mbedtls_rsa_public() returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < rsa.len - 1) && (buf[offset] == 0))
		offset++;

	*dst_len = rsa.len - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);
out:
	if (buf)
		free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.N);
	mbedtls_rsa_free(&rsa);

	return res;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_rsa_context rsa;
	int lmd_res;
	uint8_t *buf = NULL;
	unsigned long blen, offset;

	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.D = *(mbedtls_mpi *)key->d;
	rsa.N = *(mbedtls_mpi *)key->n;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		rsa.P = *(mbedtls_mpi *)key->p;
		rsa.Q = *(mbedtls_mpi *)key->q;
		rsa.QP = *(mbedtls_mpi *)key->qp;
		rsa.DP = *(mbedtls_mpi *)key->dp;
		rsa.DQ = *(mbedtls_mpi *)key->dq;
	}

	rsa.len = mbedtls_mpi_size(&rsa.N);

	blen = LMD_MAX_BITS_PER_VARIABLE / 8;
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(buf, 0, blen);
	memcpy(buf + rsa.len - src_len, src, src_len);

	lmd_res = mbedtls_rsa_private(&rsa, NULL, NULL, buf, buf);
	switch (lmd_res) {
	case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
		EMSG("mbedtls_rsa_private() returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case 0:
		break;
	default:
		/* This will result in a panic */
		EMSG("mbedtls_rsa_private() returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < rsa.len - 1) && (buf[offset] == 0))
		offset++;

	*dst_len = rsa.len - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);
out:
	if (buf)
		free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.D);
	mbedtls_mpi_init(&rsa.N);
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		mbedtls_mpi_init(&rsa.P);
		mbedtls_mpi_init(&rsa.Q);
		mbedtls_mpi_init(&rsa.QP);
		mbedtls_mpi_init(&rsa.DP);
		mbedtls_mpi_init(&rsa.DQ);
	}
	mbedtls_rsa_free(&rsa);

	return res;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res, lmd_padding;
	unsigned long blen;
	size_t mod_size;
	void *buf = NULL;
	mbedtls_rsa_context rsa;
	mbedtls_ctr_drbg_context ctr_drbg;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = MBEDTLS_MD_NONE;

	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.D = *(mbedtls_mpi *)key->d;
	rsa.N = *(mbedtls_mpi *)key->n;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		rsa.P = *(mbedtls_mpi *)key->p;
		rsa.Q = *(mbedtls_mpi *)key->q;
		rsa.QP = *(mbedtls_mpi *)key->qp;
		rsa.DP = *(mbedtls_mpi *)key->dp;
		rsa.DQ = *(mbedtls_mpi *)key->dq;
	}

	/*
	 * Use a temporary buffer since we don't know exactly how large
	 * the required size of the out buffer without doing a partial
	 * decrypt. We know the upper bound though.
	 */
	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		mod_size = crypto_bignum_num_bytes(key->n);
		blen = mod_size - 11;
		lmd_padding = MBEDTLS_RSA_PKCS_V15;
	} else {
		/* Decoded message is always shorter than encrypted message */
		blen = src_len;
		lmd_padding = MBEDTLS_RSA_PKCS_V21;
	}

	rsa.len =  crypto_bignum_num_bytes(key->n);

	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (pk_info == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/*
	 * TEE_ALG_RSAES_PKCS1_V1_5 is invalid in hash. But its hash algo will
	 * not be used in rsa, so skip it here.
	 */
	if (algo != TEE_ALG_RSAES_PKCS1_V1_5) {
		md_algo = tee_algo_to_mbedtls_hash_algo(algo);
		if (md_algo == MBEDTLS_MD_NONE) {
			res = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
	}

	mbedtls_rsa_set_padding(&rsa, lmd_padding, md_algo);

	mbedtls_ctr_drbg_init(&ctr_drbg);
	lmd_res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbd_rand, NULL, NULL, 0);
	if (lmd_res != 0) {
		EMSG(" failed\n  ! mbedtls_ctr_drbg_seed ret is 0x%x\n",
				-lmd_res);
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	if (lmd_padding == MBEDTLS_RSA_PKCS_V15)
		lmd_res = pk_info->decrypt_func(&rsa, src, src_len, buf, &blen,
						blen, NULL, NULL);
	else
		lmd_res = pk_info->decrypt_func(&rsa, src, src_len, buf, &blen,
						blen, mbedtls_ctr_drbg_random,
						&ctr_drbg);
	switch (lmd_res) {
	case MBEDTLS_ERR_RSA_INVALID_PADDING:
	case MBEDTLS_ERR_PK_TYPE_MISMATCH:
	case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
		EMSG("decrypt_func() returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case 0:
		break;
	default:
		/* This will result in a panic */
		EMSG("decrypt_func() returned 0x%x\n", -lmd_res);
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
	mbedtls_ctr_drbg_free(&ctr_drbg);
	if (buf)
		free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.D);
	mbedtls_mpi_init(&rsa.N);
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		mbedtls_mpi_init(&rsa.P);
		mbedtls_mpi_init(&rsa.Q);
		mbedtls_mpi_init(&rsa.QP);
		mbedtls_mpi_init(&rsa.DP);
		mbedtls_mpi_init(&rsa.DQ);
	}
	mbedtls_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res, lmd_padding;
	size_t mod_size;
	mbedtls_rsa_context rsa;
	mbedtls_ctr_drbg_context ctr_drbg;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = MBEDTLS_MD_NONE;

	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.N = *(mbedtls_mpi *)key->n;

	mod_size = crypto_bignum_num_bytes(key->n);
	if (*dst_len < mod_size) {
		*dst_len = mod_size;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = mod_size;
	rsa.len = mod_size;

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5)
		lmd_padding = MBEDTLS_RSA_PKCS_V15;
	else
		lmd_padding = MBEDTLS_RSA_PKCS_V21;

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (pk_info == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/*
	 * TEE_ALG_RSAES_PKCS1_V1_5 is invalid in hash. But its hash algo will
	 * not be used in rsa, so skip it here.
	 */
	if (algo != TEE_ALG_RSAES_PKCS1_V1_5) {
		md_algo = tee_algo_to_mbedtls_hash_algo(algo);
		if (md_algo == MBEDTLS_MD_NONE) {
			res = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
	}

	mbedtls_rsa_set_padding(&rsa, lmd_padding, md_algo);

	mbedtls_ctr_drbg_init(&ctr_drbg);
	lmd_res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbd_rand, NULL, NULL, 0);
	if (lmd_res != 0) {
		EMSG(" failed\n  ! mbedtls_ctr_drbg_seed ret is 0x%x\n",
					-lmd_res);
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	lmd_res = pk_info->encrypt_func(&rsa, src, src_len, dst, dst_len,
					*dst_len, mbedtls_ctr_drbg_random,
					&ctr_drbg);

	switch (lmd_res) {
	case MBEDTLS_ERR_RSA_INVALID_PADDING:
	case MBEDTLS_ERR_PK_TYPE_MISMATCH:
	case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
		EMSG("encrypt_func() returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	case 0:
		break;
	default:
		/* This will result in a panic */
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = TEE_SUCCESS;
out:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.N);
	mbedtls_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len)
{
	TEE_Result res;
	int lmd_res, lmd_padding;
	size_t mod_size, hash_size;
	mbedtls_rsa_context rsa;
	mbedtls_ctr_drbg_context ctr_drbg;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo;

	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.D = *(mbedtls_mpi *)key->d;
	rsa.N = *(mbedtls_mpi *)key->n;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		rsa.P = *(mbedtls_mpi *)key->p;
		rsa.Q = *(mbedtls_mpi *)key->q;
		rsa.QP = *(mbedtls_mpi *)key->qp;
		rsa.DP = *(mbedtls_mpi *)key->dp;
		rsa.DQ = *(mbedtls_mpi *)key->dq;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		lmd_padding = MBEDTLS_RSA_PKCS_V15;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		lmd_padding = MBEDTLS_RSA_PKCS_V21;
		break;
	default:
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

	mod_size = crypto_bignum_num_bytes(key->n);
	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}
	rsa.len = mod_size;

	md_algo = tee_algo_to_mbedtls_hash_algo(algo);
	if (md_algo == MBEDTLS_MD_NONE) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (pk_info == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	mbedtls_rsa_set_padding(&rsa, lmd_padding, md_algo);

	mbedtls_ctr_drbg_init(&ctr_drbg);
	lmd_res = mbedtls_ctr_drbg_seed(&ctr_drbg,
		mbd_rand, NULL, NULL, 0);
	if (lmd_res != 0) {
		EMSG(" failed\n  ! mbedtls_ctr_drbg_seed ret is 0x%x\n",
			-lmd_res);
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	if (lmd_padding == MBEDTLS_RSA_PKCS_V15)
		lmd_res = pk_info->sign_func(&rsa, md_algo, msg, msg_len, sig,
					     sig_len, NULL, NULL);
	else
		lmd_res = pk_info->sign_func(&rsa, md_algo, msg, msg_len, sig,
					     sig_len, mbedtls_ctr_drbg_random,
					     &ctr_drbg);
	if (lmd_res != 0) {
		EMSG("sign_func failed, returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}
	res = TEE_SUCCESS;
err:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.D);
	mbedtls_mpi_init(&rsa.N);
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		mbedtls_mpi_init(&rsa.P);
		mbedtls_mpi_init(&rsa.Q);
		mbedtls_mpi_init(&rsa.QP);
		mbedtls_mpi_init(&rsa.DP);
		mbedtls_mpi_init(&rsa.DQ);
	}
	mbedtls_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
{
	TEE_Result res;
	int lmd_res, lmd_padding;
	size_t hash_size, bigint_size;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo;

	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.N = *(mbedtls_mpi *)key->n;

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
		&hash_size);
	if (res != TEE_SUCCESS)
		goto err;

	if (msg_len != hash_size) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	bigint_size = crypto_bignum_num_bytes(key->n);
	if (sig_len < bigint_size) {
		res = TEE_ERROR_MAC_INVALID;
		goto err;
	}

	rsa.len = bigint_size;

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		lmd_padding = MBEDTLS_RSA_PKCS_V15;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		lmd_padding = MBEDTLS_RSA_PKCS_V21;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	md_algo = tee_algo_to_mbedtls_hash_algo(algo);
	if (md_algo == MBEDTLS_MD_NONE) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (pk_info == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	mbedtls_rsa_set_padding(&rsa, lmd_padding, md_algo);

	lmd_res = pk_info->verify_func(&rsa, md_algo, msg, msg_len,
				       sig, sig_len);
	if (lmd_res != 0) {
		EMSG("verify_func failed, returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto err;
	}
	res = TEE_SUCCESS;
err:
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.N);
	mbedtls_rsa_free(&rsa);
	return res;
}

#endif /* CFG_CRYPTO_RSA */

#if defined(CFG_CRYPTO_DSA)

TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s,
					       size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}


TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t key_size)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dsa_sign(uint32_t algo, struct dsa_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo, struct dsa_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

#endif /* CFG_CRYPTO_DSA */

#if defined(CFG_CRYPTO_DH)

TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s,
					   size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->g = crypto_bignum_allocate(key_size_bits);
	if (!(s->g))
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!(s->p))
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!(s->y))
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!(s->x))
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!(s->q))
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
	int lmd_res;
	mbedtls_dhm_context dhm;
	unsigned char *buf = NULL;

	mbedtls_dhm_init(&dhm);

	dhm.G = *(mbedtls_mpi *)key->g;
	dhm.P = *(mbedtls_mpi *)key->p;

	dhm.len = crypto_bignum_num_bytes(key->p);

	if (xbits == 0)
		xbits = dhm.len;
	else
		xbits = xbits / 8;

	buf = malloc(dhm.len);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	lmd_res = mbedtls_dhm_make_public(&dhm, (int)xbits, buf,
					  dhm.len, mbd_rand, NULL);
	if (lmd_res != 0) {
		EMSG("mbedtls_dhm_make_public err, return is 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		crypto_bignum_bin2bn(buf, xbits / 8, key->y);
		crypto_bignum_copy(key->x, (void *)&dhm.X);
		res = TEE_SUCCESS;
	}
out:
	if (buf)
		free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&dhm.G);
	mbedtls_mpi_init(&dhm.P);
	mbedtls_dhm_free(&dhm);
	return res;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	TEE_Result res;
	int lmd_res;
	mbedtls_dhm_context dhm;
	unsigned char *buf = NULL;
	size_t olen;

	mbedtls_dhm_init(&dhm);

	dhm.G = *(mbedtls_mpi *)private_key->g;
	dhm.P = *(mbedtls_mpi *)private_key->p;
	dhm.GX = *(mbedtls_mpi *)private_key->y;
	dhm.X = *(mbedtls_mpi *)private_key->x;
	dhm.GY = *(mbedtls_mpi *)public_key;

	dhm.len = crypto_bignum_num_bytes(private_key->p);

	buf = malloc(dhm.len);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	lmd_res = mbedtls_dhm_calc_secret(&dhm, buf, dhm.len,
					  &olen, mbd_rand, NULL);
	if (lmd_res != 0) {
		EMSG("mbedtls_dhm_calc_secret failed, ret is 0x%x\n", -lmd_res);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		crypto_bignum_bin2bn(buf, olen, secret);
		res = TEE_SUCCESS;
	}
out:
	if (buf)
		free(buf);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&dhm.G);
	mbedtls_mpi_init(&dhm.P);
	mbedtls_mpi_init(&dhm.GX);
	mbedtls_mpi_init(&dhm.X);
	mbedtls_mpi_init(&dhm.GY);
	mbedtls_dhm_free(&dhm);
	return res;
}

#endif /* CFG_CRYPTO_DH */

#if defined(CFG_CRYPTO_ECC)

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->d = crypto_bignum_allocate(key_size_bits);
	if (!(s->d))
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!(s->x))
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!(s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
					       size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!(s->x))
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!(s->y))
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

/*
 * Clear some memory that was used to prepare the context
 */
static void ecc_clear_precomputed(mbedtls_ecp_group *grp)
{
	if (grp->T != NULL) {
		size_t i;

		for (i = 0; i < grp->T_size; i++)
			mbedtls_ecp_point_free(&grp->T[i]);
		free(grp->T);
	}
	grp->T = NULL;
	grp->T_size = 0;
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	TEE_Result res;
	int lmd_res;
	mbedtls_ecdsa_context ecdsa;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;

	res = ecc_get_keysize(key->curve, 0, &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	mbedtls_ecdsa_init(&ecdsa);

	/* Generate the ECC key */
	lmd_res = mbedtls_ecdsa_genkey(&ecdsa, key->curve, mbd_rand, NULL);
	if (lmd_res != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("mbedtls_ecdsa_genkey failed.\n");
		goto exit;
	}
	ecc_clear_precomputed(&ecdsa.grp);

	/* check the size of the keys */
	if ((mbedtls_mpi_bitlen(&ecdsa.Q.X) > key_size_bits) ||
	    (mbedtls_mpi_bitlen(&ecdsa.Q.Y) > key_size_bits) ||
	    (mbedtls_mpi_bitlen(&ecdsa.d) > key_size_bits)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Check the size of the keys failed.\n");
		goto exit;
	}

	/* check LMD is returning z==1 */
	if (mbedtls_mpi_bitlen(&ecdsa.Q.Z) != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Check LMD failed.\n");
		goto exit;
	}

	/* Copy the key */
	crypto_bignum_copy(key->d, (void *)&ecdsa.d);
	crypto_bignum_copy(key->x, (void *)&ecdsa.Q.X);
	crypto_bignum_copy(key->y, (void *)&ecdsa.Q.Y);

	res = TEE_SUCCESS;
exit:
	mbedtls_ecdsa_free(&ecdsa);		/* Free the temporary key */
	return res;
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	int lmd_res;
	const mbedtls_pk_info_t *pk_info = NULL;
	mbedtls_ecdsa_context ecdsa;
	size_t key_size_bytes, key_size_bits;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi r, s;

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);
	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	ecdsa.d = *(mbedtls_mpi *)key->d;

	res = ecc_get_keysize(key->curve, algo, &key_size_bytes,
			&key_size_bits);
	if (res != TEE_SUCCESS)
		goto err;

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA);
	if (pk_info == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	mbedtls_ctr_drbg_init(&ctr_drbg);
	lmd_res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbd_rand, NULL, NULL, 0);
	if (lmd_res != 0) {
		EMSG(" failed\n  ! mbedtls_ctr_drbg_seed ret is 0x%x\n",
				-lmd_res);
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	lmd_res = mbedtls_ecdsa_sign(&ecdsa.grp, &r, &s, &ecdsa.d, msg,
				msg_len, mbedtls_ctr_drbg_random, &ctr_drbg);

	if (lmd_res == 0) {
		*sig_len = 2 * key_size_bytes;
		memset(sig, 0, *sig_len);
		mbedtls_mpi_write_binary(&r, sig + *sig_len/2 -
					mbedtls_mpi_size(&r),
					mbedtls_mpi_size(&r));

		mbedtls_mpi_write_binary(&s, sig + *sig_len -
					mbedtls_mpi_size(&s),
					mbedtls_mpi_size(&s));
		res = TEE_SUCCESS;
	} else {
		EMSG("mbedtls_ecdsa_sign failed, returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_GENERIC;
	}
err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdsa.d);
	mbedtls_ecdsa_free(&ecdsa);
	return res;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res;
	mbedtls_ecdsa_context ecdsa;
	size_t key_size_bytes, key_size_bits;
	uint8_t one[1] = { 1 };
	mbedtls_mpi r, s;

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);

	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	ecdsa.Q.X = *(mbedtls_mpi *)key->x;
	ecdsa.Q.Y = *(mbedtls_mpi *)key->y;
	mbedtls_mpi_read_binary(&ecdsa.Q.Z, one, sizeof(one));

	res = ecc_get_keysize(key->curve, algo,
			      &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	/* check keysize vs sig_len */
	if ((key_size_bytes * 2) != sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	mbedtls_mpi_read_binary(&r, sig, sig_len / 2);
	mbedtls_mpi_read_binary(&s, sig + sig_len / 2, sig_len / 2);

	lmd_res = mbedtls_ecdsa_verify(&ecdsa.grp, msg, msg_len, &ecdsa.Q,
				       &r, &s);
	if (lmd_res != 0) {
		EMSG("mbedtls_ecdsa_verify failed, returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_GENERIC;
		goto err;
	}
err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdsa.Q.X);
	mbedtls_mpi_init(&ecdsa.Q.Y);
	mbedtls_ecdsa_free(&ecdsa);
	return res;
}

TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res;
	uint8_t one[1] = { 1 };
	mbedtls_ecdh_context ecdh;
	size_t out_len;

	mbedtls_ecdh_init(&ecdh);
	lmd_res = mbedtls_ecp_group_load(&ecdh.grp, private_key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ecdh.d = *(mbedtls_mpi *)private_key->d;
	ecdh.Qp.X = *(mbedtls_mpi *)public_key->x;
	ecdh.Qp.Y = *(mbedtls_mpi *)public_key->y;
	mbedtls_mpi_read_binary(&ecdh.Qp.Z, one, sizeof(one));

	lmd_res = mbedtls_ecdh_calc_secret(&ecdh, &out_len, secret,
				*secret_len, mbd_rand, NULL);
	if (lmd_res != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	*secret_len = out_len;
out:
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&ecdh.d);
	mbedtls_mpi_init(&ecdh.Qp.X);
	mbedtls_mpi_init(&ecdh.Qp.Y);
	mbedtls_ecdh_free(&ecdh);
	return res;
}
#endif /* CFG_CRYPTO_ECC */

#endif /* _CFG_CRYPTO_WITH_ACIPHER */

/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_CIPHER)
TEE_Result crypto_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_cipher_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode __maybe_unused,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2 __maybe_unused,
			      size_t key2_len __maybe_unused,
			      const uint8_t *iv __maybe_unused,
			      size_t iv_len __maybe_unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				bool last_block __maybe_unused,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_cipher_final(void *ctx, uint32_t algo)
{
}
#endif /* _CFG_CRYPTO_WITH_CIPHER */

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/

#if defined(_CFG_CRYPTO_WITH_MAC)
TEE_Result crypto_mac_get_ctx_size(uint32_t algo, size_t *size)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_final(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t digest_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
size_t crypto_aes_ccm_get_ctx_size(void)
{
	return 0;
}

TEE_Result crypto_aes_ccm_init(void *ctx, TEE_OperationMode mode __unused,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_update_aad(void *ctx, const uint8_t *data, size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t len, uint8_t *dst_data)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_enc_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    uint8_t *dst_tag, size_t *dst_tag_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_dec_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    const uint8_t *tag, size_t tag_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_ccm_final(void *ctx)
{
}
#endif /*CFG_CRYPTO_CCM*/

#if defined(CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB)
size_t crypto_aes_gcm_get_ctx_size(void)
{
	return 0;
}

TEE_Result crypto_aes_gcm_init(void *ctx, TEE_OperationMode mode __unused,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_update_aad(void *ctx, const uint8_t *data, size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t len, uint8_t *dst_data)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_enc_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    uint8_t *dst_tag, size_t *dst_tag_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_dec_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    const uint8_t *tag, size_t tag_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_gcm_final(void *ctx)
{
}
#endif /*CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB*/

/******************************************************************************
 * Pseudo Random Number Generator
 ******************************************************************************/
TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_rng_add_entropy(const uint8_t *inbuf, size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_init(void)
{
	return TEE_SUCCESS;
}

#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	mbedtls_md_context_t hs;
	uint8_t digest[TEE_SHA256_HASH_SIZE];

	if (crypto_hash_init(&hs, TEE_ALG_SHA256) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;
	if (crypto_hash_update(&hs, TEE_ALG_SHA256, data,
		data_size) != TEE_SUCCESS) {
		return TEE_ERROR_GENERIC;
	}
	if (crypto_hash_final(&hs, TEE_ALG_SHA256, digest,
			sizeof(digest)) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;
	if (buf_compare_ct(digest, hash, sizeof(digest)) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
#endif

TEE_Result rng_generate(void *buffer, size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, unsigned int *rounds)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_enc_block(const void *enc_key, unsigned int rounds,
			  const void *src, void *dst)
{
}
