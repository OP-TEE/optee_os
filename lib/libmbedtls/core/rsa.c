// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

#include "mbed_helpers.h"

static TEE_Result get_tee_result(int lmd_res)
{
	switch (lmd_res) {
	case 0:
		return TEE_SUCCESS;
	case MBEDTLS_ERR_RSA_PRIVATE_FAILED +
		MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
	case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
	case MBEDTLS_ERR_RSA_INVALID_PADDING:
	case MBEDTLS_ERR_PK_TYPE_MISMATCH:
		return TEE_ERROR_BAD_PARAMETERS;
	case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
		return TEE_ERROR_SHORT_BUFFER;
	default:
		return TEE_ERROR_BAD_STATE;
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

static void rsa_init_from_key_pair(mbedtls_rsa_context *rsa,
				struct rsa_keypair *key)
{
	mbedtls_rsa_init(rsa, 0, 0);

	rsa->E = *(mbedtls_mpi *)key->e;
	rsa->N = *(mbedtls_mpi *)key->n;
	rsa->D = *(mbedtls_mpi *)key->d;
	if (key->p && crypto_bignum_num_bytes(key->p)) {
		rsa->P = *(mbedtls_mpi *)key->p;
		rsa->Q = *(mbedtls_mpi *)key->q;
		rsa->QP = *(mbedtls_mpi *)key->qp;
		rsa->DP = *(mbedtls_mpi *)key->dp;
		rsa->DQ = *(mbedtls_mpi *)key->dq;
	}
	rsa->len = mbedtls_mpi_size(&rsa->N);
}

static void mbd_rsa_free(mbedtls_rsa_context *rsa)
{
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa->E);
	mbedtls_mpi_init(&rsa->N);
	mbedtls_mpi_init(&rsa->D);
	if (mbedtls_mpi_size(&rsa->P)) {
		mbedtls_mpi_init(&rsa->P);
		mbedtls_mpi_init(&rsa->Q);
		mbedtls_mpi_init(&rsa->QP);
		mbedtls_mpi_init(&rsa->DP);
		mbedtls_mpi_init(&rsa->DQ);
	}
	mbedtls_rsa_free(rsa);
}

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->e = crypto_bignum_allocate(key_size_bits);
	if (!s->e)
		goto err;
	s->d = crypto_bignum_allocate(key_size_bits);
	if (!s->d)
		goto err;
	s->n = crypto_bignum_allocate(key_size_bits);
	if (!s->n)
		goto err;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!s->p)
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!s->q)
		goto err;
	s->qp = crypto_bignum_allocate(key_size_bits);
	if (!s->qp)
		goto err;
	s->dp = crypto_bignum_allocate(key_size_bits);
	if (!s->dp)
		goto err;
	s->dq = crypto_bignum_allocate(key_size_bits);
	if (!s->dq)
		goto err;

	return TEE_SUCCESS;
err:
	crypto_acipher_free_rsa_keypair(s);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
					       size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->e = crypto_bignum_allocate(key_size_bits);
	if (!s->e)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->n = crypto_bignum_allocate(key_size_bits);
	if (!s->n)
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

void crypto_acipher_free_rsa_keypair(struct rsa_keypair *s)
{
	if (!s)
		return;
	crypto_bignum_free(s->e);
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->n);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	crypto_bignum_free(s->qp);
	crypto_bignum_free(s->dp);
	crypto_bignum_free(s->dq);
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_rsa_context rsa;
	mbedtls_ctr_drbg_context rngctx;
	int lmd_res = 0;
	uint32_t e = 0;

	mbedtls_ctr_drbg_init(&rngctx);
	if (mbedtls_ctr_drbg_seed(&rngctx, mbd_rand, NULL, NULL, 0))
		return TEE_ERROR_BAD_STATE;

	memset(&rsa, 0, sizeof(rsa));
	mbedtls_rsa_init(&rsa, 0, 0);

	/* get the public exponent */
	mbedtls_mpi_write_binary((mbedtls_mpi *)key->e,
				 (unsigned char *)&e, sizeof(uint32_t));

	e = TEE_U32_FROM_BIG_ENDIAN(e);
	lmd_res = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &rngctx,
				      key_size, (int)e);
	mbedtls_ctr_drbg_free(&rngctx);
	if (lmd_res != 0) {
		res = get_tee_result(lmd_res);
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

	mbedtls_rsa_free(&rsa);

	return res;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_rsa_context rsa;
	int lmd_res = 0;
	uint8_t *buf = NULL;
	unsigned long blen = 0;
	unsigned long offset = 0;

	memset(&rsa, 0, sizeof(rsa));
	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.N = *(mbedtls_mpi *)key->n;

	rsa.len = crypto_bignum_num_bytes((void *)&rsa.N);

	blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(buf, 0, blen);
	memcpy(buf + rsa.len - src_len, src, src_len);

	lmd_res = mbedtls_rsa_public(&rsa, buf, buf);
	if (lmd_res != 0) {
		FMSG("mbedtls_rsa_public() returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < rsa.len - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < rsa.len - offset) {
		*dst_len = rsa.len - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = rsa.len - offset;
	memcpy(dst, buf + offset, *dst_len);
out:
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
	int lmd_res = 0;
	uint8_t *buf = NULL;
	unsigned long blen = 0;
	unsigned long offset = 0;

	memset(&rsa, 0, sizeof(rsa));
	rsa_init_from_key_pair(&rsa, key);

	blen = CFG_CORE_BIGNUM_MAX_BITS / 8;
	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memset(buf, 0, blen);
	memcpy(buf + rsa.len - src_len, src, src_len);

	lmd_res = mbedtls_rsa_private(&rsa, NULL, NULL, buf, buf);
	if (lmd_res != 0) {
		FMSG("mbedtls_rsa_private() returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
		goto out;
	}

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < rsa.len - 1) && (buf[offset] == 0))
		offset++;

	if (*dst_len < rsa.len - offset) {
		*dst_len = rsa.len - offset;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	*dst_len = rsa.len - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);
out:
	if (buf)
		free(buf);
	mbd_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	int lmd_padding = 0;
	size_t blen = 0;
	size_t mod_size = 0;
	void *buf = NULL;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = MBEDTLS_MD_NONE;

	memset(&rsa, 0, sizeof(rsa));
	rsa_init_from_key_pair(&rsa, key);

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

	buf = malloc(blen);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (!pk_info) {
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

	if (lmd_padding == MBEDTLS_RSA_PKCS_V15)
		lmd_res = pk_info->decrypt_func(&rsa, src, src_len, buf, &blen,
						blen, NULL, NULL);
	else
		lmd_res = pk_info->decrypt_func(&rsa, src, src_len, buf, &blen,
						blen, mbd_rand, NULL);
	if (lmd_res != 0) {
		FMSG("decrypt_func() returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
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
	mbd_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	int lmd_padding = 0;
	size_t mod_size = 0;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = MBEDTLS_MD_NONE;

	memset(&rsa, 0, sizeof(rsa));
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
	if (!pk_info) {
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

	lmd_res = pk_info->encrypt_func(&rsa, src, src_len, dst, dst_len,
					*dst_len, mbd_rand, NULL);
	if (lmd_res != 0) {
		FMSG("encrypt_func() returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
		goto out;
	}
	res = TEE_SUCCESS;
out:
	/* Reset mpi to skip freeing here, those mpis will be freed with key */
	mbedtls_mpi_init(&rsa.E);
	mbedtls_mpi_init(&rsa.N);
	mbedtls_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len __unused, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	int lmd_padding = 0;
	size_t mod_size = 0;
	size_t hash_size = 0;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = 0;

	memset(&rsa, 0, sizeof(rsa));
	rsa_init_from_key_pair(&rsa, key);

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

	res = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
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
	if (!pk_info) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	mbedtls_rsa_set_padding(&rsa, lmd_padding, md_algo);

	if (lmd_padding == MBEDTLS_RSA_PKCS_V15)
		lmd_res = pk_info->sign_func(&rsa, md_algo, msg, msg_len, sig,
					     sig_len, NULL, NULL);
	else
		lmd_res = pk_info->sign_func(&rsa, md_algo, msg, msg_len, sig,
					     sig_len, mbd_rand, NULL);
	if (lmd_res != 0) {
		FMSG("sign_func failed, returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
		goto err;
	}
	res = TEE_SUCCESS;
err:
	mbd_rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len __unused,
					const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res = 0;
	int lmd_padding = 0;
	size_t hash_size = 0;
	size_t bigint_size = 0;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = 0;

	memset(&rsa, 0, sizeof(rsa));
	mbedtls_rsa_init(&rsa, 0, 0);

	rsa.E = *(mbedtls_mpi *)key->e;
	rsa.N = *(mbedtls_mpi *)key->n;

	res = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
				      &hash_size);
	if (res != TEE_SUCCESS)
		goto err;

	if (msg_len != hash_size) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	bigint_size = crypto_bignum_num_bytes(key->n);
	if (sig_len < bigint_size) {
		res = TEE_ERROR_SIGNATURE_INVALID;
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
	if (!pk_info) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	mbedtls_rsa_set_padding(&rsa, lmd_padding, md_algo);

	lmd_res = pk_info->verify_func(&rsa, md_algo, msg, msg_len,
				       sig, sig_len);
	if (lmd_res != 0) {
		FMSG("verify_func failed, returned 0x%x", -lmd_res);
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
