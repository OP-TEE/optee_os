// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/aes-ccm.h>
#include <crypto/aes-gcm.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(CFG_CRYPTO_AES)
#include "mbedtls/aes.h"
#endif
#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#endif
#endif
#if defined(CFG_CRYPTO_CCM)
#include "mbedtls/ccm.h"
#endif
#if defined(_CFG_CRYPTO_WITH_CIPHER)
#include "mbedtls/cipher.h"
#include "mbedtls/cipher_internal.h"
#endif
#if defined(CFG_CRYPTO_CMAC)
#include "mbedtls/cmac.h"
#endif
#if defined(CFG_CRYPTO_DES)
#include "mbedtls/des.h"
#endif
#if defined(CFG_CRYPTO_DH)
#include "mbedtls/dhm.h"
#endif
#if defined(CFG_CRYPTO_ECC)
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#endif
#if defined(CFG_CRYPTO_HMAC)
#include "mbedtls/md_internal.h"
#include "mbedtls/md.h"
#endif
#if defined(CFG_CRYPTO_MD5)
#include "mbedtls/md5.h"
#endif
#if defined(CFG_CRYPTO_SHA1)
#include "mbedtls/sha1.h"
#endif
#if defined(CFG_CRYPTO_SHA224) || defined(CFG_CRYPTO_SHA256)
#include "mbedtls/sha256.h"
#endif
#if defined(CFG_CRYPTO_SHA384) || defined(CFG_CRYPTO_SHA512)
#include "mbedtls/sha512.h"
#endif
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>
#include <util.h>

#if defined(CFG_CRYPTO_AES) || defined(_CFG_CRYPTO_WITH_MAC) \
	|| defined(_CFG_CRYPTO_WITH_ACIPHER) || defined(CFG_CRYPTO_ECC)
/* Translate mbedtls result to TEE result */
static TEE_Result get_tee_result(int lmd_res)
{
	switch (lmd_res) {
#if defined(_CFG_CRYPTO_WITH_CIPHER)
	case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
		return TEE_ERROR_NOT_SUPPORTED;
	case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
		return TEE_ERROR_BAD_PARAMETERS;
	case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
		return TEE_ERROR_OUT_OF_MEMORY;
#endif
#if defined(_CFG_CRYPTO_WITH_MAC)
	case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
		return TEE_ERROR_BAD_PARAMETERS;
	case MBEDTLS_ERR_MD_ALLOC_FAILED:
		return TEE_ERROR_OUT_OF_MEMORY;
#endif
#if defined(_CFG_CRYPTO_WITH_ACIPHER)
	case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
	case MBEDTLS_ERR_RSA_INVALID_PADDING:
	case MBEDTLS_ERR_PK_TYPE_MISMATCH:
		return TEE_ERROR_BAD_PARAMETERS;
	case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
		return TEE_ERROR_SHORT_BUFFER;
#endif
#if defined(CFG_CRYPTO_ECC)
	case MBEDTLS_ERR_ECP_VERIFY_FAILED:
		return TEE_ERROR_SIGNATURE_INVALID;
	case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;
#endif
	case 0:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_STATE;
	}
}
#endif /*
	* defined(CFG_CRYPTO_AES) || defined(_CFG_CRYPTO_WITH_MAC) \
	* || defined(_CFG_CRYPTO_WITH_ACIPHER) || defined(CFG_CRYPTO_ECC)
	*/

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
static int mbd_rand(void *rng_state __unused, unsigned char *output,
			size_t len)
{
	if (crypto_rng_read(output, len))
		return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	return 0;
}
#endif /* defined(_CFG_CRYPTO_WITH_ACIPHER) */

#if defined(_CFG_CRYPTO_WITH_CIPHER) || defined(_CFG_CRYPTO_WITH_MAC) || \
	defined(_CFG_CRYPTO_WITH_AUTHENC)
/*
 * Get the Mbedtls cipher info given a TEE Algorithm "algo"
 * Return
 * - A pointer to a valid mbedtls_cipher_definition_t on success
 * - NULL in case of error
 */
static const mbedtls_cipher_info_t *get_cipher_info(uint32_t algo,
						size_t key_len)
{
	switch (algo) {
#if defined(CFG_CRYPTO_AES)
	case TEE_ALG_AES_ECB_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_128_ECB);
		else if (key_len == 192)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_192_ECB);
		else if (key_len == 256)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_256_ECB);
		else
			return NULL;
	case TEE_ALG_AES_CBC_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_128_CBC);
		else if (key_len == 192)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_192_CBC);
		else if (key_len == 256)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_256_CBC);
		else
			return NULL;
	case TEE_ALG_AES_CTR:
		if (key_len == 128)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_128_CTR);
		else if (key_len == 192)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_192_CTR);
		else if (key_len == 256)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_AES_256_CTR);
		else
			return NULL;
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
		return NULL;
#endif
#if defined(CFG_CRYPTO_DES)
	case TEE_ALG_DES_ECB_NOPAD:
		if (key_len == 64)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_DES_ECB);
		else
			return NULL;
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		return NULL;
	case TEE_ALG_DES_CBC_NOPAD:
		if (key_len == 64)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_DES_CBC);
		else
			return NULL;
	case TEE_ALG_DES3_ECB_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_DES_EDE_ECB);
		else if (key_len == 192)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_DES_EDE3_ECB);
		else
			return NULL;
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return NULL;
	case TEE_ALG_DES3_CBC_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_DES_EDE_CBC);
		else if (key_len == 192)
			return mbedtls_cipher_info_from_type(
						MBEDTLS_CIPHER_DES_EDE3_CBC);
		else
			return NULL;
#endif
	default:
		return NULL;
	}
}
#endif	/* defined(_CFG_CRYPTO_WITH_CIPHER) ||
	 * defined(_CFG_CRYPTO_WITH_MAC) || defined(_CFG_CRYPTO_WITH_AUTHENC)
	 */

#if defined(CFG_CRYPTO_HMAC)
/*
 * Get mbedtls hash info given a TEE Algorithm "algo"
 * Return
 * - mbedtls_md_info_t * in case of success,
 * - NULL in case of error
 */
static const mbedtls_md_info_t *get_hash_info(uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
		return mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA224);
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
#endif
	default:
		return NULL;
	}
}
#endif /*  defined(CFG_CRYPTO_HMAC) */

#if defined(CFG_CRYPTO_RSA)

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
#endif /*  defined(CFG_CRYPTO_RSA) */

/******************************************************************************
 * Message digest functions
 ******************************************************************************/
#if defined(_CFG_CRYPTO_WITH_HASH)
static TEE_Result hash_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
		*size = sizeof(mbedtls_md5_context);
		break;
#endif
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
		*size = sizeof(mbedtls_sha1_context);
		break;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
		*size = sizeof(mbedtls_sha256_context);
		break;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
		*size = sizeof(mbedtls_sha256_context);
		break;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
		*size = sizeof(mbedtls_sha512_context);
		break;
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
		*size = sizeof(mbedtls_sha512_context);
		break;
#endif
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
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
		mbedtls_sha1_init(ctx);
		mbedtls_sha1_starts(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
		mbedtls_md5_init(ctx);
		mbedtls_md5_starts(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
		mbedtls_sha256_init(ctx);
		mbedtls_sha256_starts(ctx, 1);
		break;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
		mbedtls_sha256_init(ctx);
		mbedtls_sha256_starts(ctx, 0);
		break;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
		mbedtls_sha512_init(ctx);
		mbedtls_sha512_starts(ctx, 1);
		break;
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
		mbedtls_sha512_init(ctx);
		mbedtls_sha512_starts(ctx, 0);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result crypto_hash_update(void *ctx, uint32_t algo,
				      const uint8_t *data, size_t len)
{
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
		mbedtls_sha1_update(ctx, data, len);
		break;
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
		mbedtls_md5_update(ctx, data, len);
		break;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
		mbedtls_sha256_update(ctx, data, len);
		break;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
		mbedtls_sha256_update(ctx, data, len);
		break;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
		mbedtls_sha512_update(ctx, data, len);
		break;
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
		mbedtls_sha512_update(ctx, data, len);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result crypto_hash_final(void *ctx, uint32_t algo, uint8_t *digest,
			     size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	size_t hash_size;
	uint8_t block_digest[TEE_MAX_HASH_SIZE];
	uint8_t *tmp_digest;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_get_digest_size(algo, &hash_size);
	if (res != TEE_SUCCESS)
		return res;

	if (hash_size > len) {
		if (hash_size > sizeof(block_digest))
			return TEE_ERROR_BAD_STATE;
		tmp_digest = block_digest; /* use a tempory buffer */
	} else {
		tmp_digest = digest;
	}

	switch (algo) {
#if defined(CFG_CRYPTO_SHA1)
	case TEE_ALG_SHA1:
		mbedtls_sha1_finish(ctx, tmp_digest);
		break;
#endif
#if defined(CFG_CRYPTO_MD5)
	case TEE_ALG_MD5:
		mbedtls_md5_finish(ctx, tmp_digest);
		break;
#endif
#if defined(CFG_CRYPTO_SHA224)
	case TEE_ALG_SHA224:
		mbedtls_sha256_finish(ctx, tmp_digest);
		break;
#endif
#if defined(CFG_CRYPTO_SHA256)
	case TEE_ALG_SHA256:
		mbedtls_sha256_finish(ctx, tmp_digest);
		break;
#endif
#if defined(CFG_CRYPTO_SHA384)
	case TEE_ALG_SHA384:
		mbedtls_sha512_finish(ctx, tmp_digest);
		break;
#endif
#if defined(CFG_CRYPTO_SHA512)
	case TEE_ALG_SHA512:
		mbedtls_sha512_finish(ctx, tmp_digest);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	if (hash_size > len)
		memcpy(digest, tmp_digest, len);

	return res;
}
#endif /* _CFG_CRYPTO_WITH_HASH */

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
#define ciL		(sizeof(mbedtls_mpi_uint))	/* chars in limb  */
#define biL		(ciL << 3)			/* bits  in limb  */
#define BITS_TO_LIMBS(i) ((i) / biL + ((i) % biL != 0))

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
	return CMP_TRILEAN(ret, 0);
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

	if (size_bits > CFG_CORE_BIGNUM_MAX_BITS) {
		size_bits = CFG_CORE_BIGNUM_MAX_BITS;
	}

	bn = calloc(1, sizeof(mbedtls_mpi));
	if (!bn)
		return NULL;
	mbedtls_mpi_init(bn);
	if (mbedtls_mpi_grow(bn, BITS_TO_LIMBS(size_bits)) != 0) {
		free(bn);
		return NULL;
	}

	return (struct bignum *)bn;
}

void crypto_bignum_free(struct bignum *s)
{
	mbedtls_mpi_free((mbedtls_mpi *)s);
	free(s);
}

void crypto_bignum_clear(struct bignum *s)
{
	mbedtls_mpi *bn = (mbedtls_mpi *)s;

	memset(bn->p, 0, mbedtls_mpi_size((const mbedtls_mpi *)bn));
}

#if defined(CFG_CRYPTO_RSA)
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

static void rsa_free(mbedtls_rsa_context *rsa)
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
		return TEE_ERROR_OUT_OF_MEMORY;
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

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result res;
	mbedtls_rsa_context rsa;
	int lmd_res;
	uint32_t e;

	mbedtls_rsa_init(&rsa, 0, 0);

	/* get the public exponent */
	mbedtls_mpi_write_binary((mbedtls_mpi *)key->e,
				 (unsigned char *)&e, sizeof(uint32_t));

	e = TEE_U32_FROM_BIG_ENDIAN(e);
	lmd_res = mbedtls_rsa_gen_key(&rsa, mbd_rand, NULL, key_size, (int)e);
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
	/* Free the temporary key */
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

	*dst_len = rsa.len - offset;
	memcpy(dst, (char *)buf + offset, *dst_len);
out:
	if (buf)
		free(buf);
	rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	int lmd_res, lmd_padding;
	size_t blen;
	size_t mod_size;
	void *buf = NULL;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo = MBEDTLS_MD_NONE;

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
	rsa_free(&rsa);
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
	int lmd_res, lmd_padding;
	size_t mod_size;
	mbedtls_rsa_context rsa;
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
	TEE_Result res;
	int lmd_res, lmd_padding;
	size_t mod_size, hash_size;
	mbedtls_rsa_context rsa;
	const mbedtls_pk_info_t *pk_info = NULL;
	uint32_t md_algo;

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
	rsa_free(&rsa);
	return res;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len __unused,
					const uint8_t *msg,
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

#endif /* CFG_CRYPTO_RSA */

#if defined(CFG_CRYPTO_DSA)
TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key __unused,
				      size_t key_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dsa_sign(uint32_t algo __unused,
				   struct dsa_keypair *key __unused,
				   const uint8_t *msg __unused,
				   size_t msg_len __unused,
				   uint8_t *sig __unused,
				   size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo __unused,
				     struct dsa_public_key *key __unused,
				     const uint8_t *msg __unused,
				     size_t msg_len __unused,
				     const uint8_t *sig __unused,
				     size_t sig_len __unused)
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
	if (!s->g)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!s->p)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!s->q)
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->y);
	crypto_bignum_free(s->x);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key,
				     struct bignum *q __unused,
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
		FMSG("mbedtls_dhm_make_public err, return is 0x%x", -lmd_res);
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
		FMSG("mbedtls_dhm_calc_secret failed, ret is 0x%x", -lmd_res);
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
	if (!s->d)
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
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
	if (!s->x)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
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
	size_t i;

	if (grp->T) {
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
		FMSG("mbedtls_ecdsa_genkey failed.");
		goto exit;
	}
	ecc_clear_precomputed(&ecdsa.grp);

	/* check the size of the keys */
	if ((mbedtls_mpi_bitlen(&ecdsa.Q.X) > key_size_bits) ||
	    (mbedtls_mpi_bitlen(&ecdsa.Q.Y) > key_size_bits) ||
	    (mbedtls_mpi_bitlen(&ecdsa.d) > key_size_bits)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		FMSG("Check the size of the keys failed.");
		goto exit;
	}

	/* check LMD is returning z==1 */
	if (mbedtls_mpi_bitlen(&ecdsa.Q.Z) != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		FMSG("Check LMD failed.");
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
	mbedtls_mpi r, s;

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ecdsa_init(&ecdsa);
	lmd_res = mbedtls_ecp_group_load(&ecdsa.grp, key->curve);
	if (lmd_res != 0) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ecdsa.d = *(mbedtls_mpi *)key->d;

	res = ecc_get_keysize(key->curve, algo, &key_size_bytes,
			      &key_size_bits);
	if (res != TEE_SUCCESS)
		goto out;

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA);
	if (!pk_info) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	lmd_res = mbedtls_ecdsa_sign(&ecdsa.grp, &r, &s, &ecdsa.d, msg,
				     msg_len, mbd_rand, NULL);
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
		FMSG("mbedtls_ecdsa_sign failed, returned 0x%x\n", -lmd_res);
		res = TEE_ERROR_GENERIC;
	}
out:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
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
		goto out;
	}

	ecdsa.Q.X = *(mbedtls_mpi *)key->x;
	ecdsa.Q.Y = *(mbedtls_mpi *)key->y;
	mbedtls_mpi_read_binary(&ecdsa.Q.Z, one, sizeof(one));

	res = ecc_get_keysize(key->curve, algo,
			      &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* check keysize vs sig_len */
	if ((key_size_bytes * 2) != sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mbedtls_mpi_read_binary(&r, sig, sig_len / 2);
	mbedtls_mpi_read_binary(&s, sig + sig_len / 2, sig_len / 2);

	lmd_res = mbedtls_ecdsa_verify(&ecdsa.grp, msg, msg_len, &ecdsa.Q,
				       &r, &s);
	if (lmd_res != 0) {
		FMSG("mbedtls_ecdsa_verify failed, returned 0x%x", -lmd_res);
		res = get_tee_result(lmd_res);
	}
out:
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
		res = get_tee_result(lmd_res);
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

static TEE_Result cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#if defined(CFG_CRYPTO_CBC)
#endif
	case TEE_ALG_AES_CBC_NOPAD:
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_cipher_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	const mbedtls_cipher_info_t *cipher_info = NULL;
	int lmd_res;
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	/*
	 * Use a default key length for getting 'cipher_info' to do setup,
	 * and the 'cipher_info' needed be re-set after get real key length.
	 * Note that changing key length is safe since the underlaying
	 * allocation is the same.
	 */
	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		cipher_info = get_cipher_info(algo, 128);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
		cipher_info = get_cipher_info(algo, 128);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		cipher_info = get_cipher_info(algo, 128);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
		cipher_info = get_cipher_info(algo, MBEDTLS_KEY_LENGTH_DES);
		break;
	case TEE_ALG_DES3_ECB_NOPAD:
		cipher_info = get_cipher_info(algo,
					      MBEDTLS_KEY_LENGTH_DES_EDE);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
		cipher_info = get_cipher_info(algo, MBEDTLS_KEY_LENGTH_DES);
		break;
	case TEE_ALG_DES3_CBC_NOPAD:
		cipher_info = get_cipher_info(algo,
					      MBEDTLS_KEY_LENGTH_DES_EDE);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!cipher_info)
		return TEE_ERROR_NOT_SUPPORTED;

	res = cipher_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	mbedtls_cipher_init(ctx);

	lmd_res = mbedtls_cipher_setup(ctx, cipher_info);
	if (lmd_res != 0) {
		crypto_cipher_free_ctx(ctx, algo);
		FMSG("mbedtls_cipher_setup failed, res is 0x%x", -lmd_res);
		return get_tee_result(lmd_res);
	}

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
	assert(!cipher_get_ctx_size(algo, &ctx_size));
	mbedtls_cipher_free(ctx);
	free(ctx);
}

void crypto_cipher_copy_state(void *dst_ctx, void *src_ctx,
				uint32_t algo __unused)
{
	if (mbedtls_cipher_clone(dst_ctx, src_ctx) != 0)
		panic();
}

TEE_Result crypto_cipher_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2 __unused,
			      size_t key2_len __unused,
			      const uint8_t *iv,
			      size_t iv_len)
{
	const mbedtls_cipher_info_t *cipher_info = NULL;
	int lmd_res;
	int lmd_mode;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Now, re-set the cipher info according the real key length.
	 * Note that changing key length is safe since the underlaying
	 * allocation is the same.
	 */
	cipher_info = get_cipher_info(algo, key1_len * 8);
	if (!cipher_info)
		return TEE_ERROR_NOT_SUPPORTED;

	lmd_res = mbedtls_cipher_setup_info(ctx, cipher_info);
	if (lmd_res != 0) {
		FMSG("setup info failed, res is 0x%x", -lmd_res);
		return get_tee_result(lmd_res);
	}

	if (mode == TEE_MODE_ENCRYPT)
		lmd_mode = MBEDTLS_ENCRYPT;
	else
		lmd_mode = MBEDTLS_DECRYPT;
	lmd_res = mbedtls_cipher_setkey(ctx, key1, key1_len * 8, lmd_mode);
	if (lmd_res != 0) {
		FMSG("setkey failed, res is 0x%x", -lmd_res);
		return get_tee_result(lmd_res);
	}

	if (iv) {
		lmd_res = mbedtls_cipher_set_iv(ctx, iv, iv_len);
		if (lmd_res != 0) {
			FMSG("set iv failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
	}

	lmd_res = mbedtls_cipher_reset(ctx);
	if (lmd_res != 0) {
		FMSG("mbedtls_cipher_reset failed, res is 0x%x",
		     -lmd_res);
		return get_tee_result(lmd_res);
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode __unused,
				bool last_block __unused,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	size_t blk_size __maybe_unused;
	int lmd_res;
	size_t olen;
	size_t finish_olen;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
		blk_size = mbedtls_cipher_get_block_size(ctx);
		if (len % blk_size != 0)
			return TEE_ERROR_BAD_PARAMETERS;
		while (len) {
			lmd_res = mbedtls_cipher_update(ctx, data, blk_size,
							dst, &olen);
			if (lmd_res != 0) {
				FMSG("update failed, res is 0x%x", -lmd_res);
				return get_tee_result(lmd_res);
			}
			data += olen;
			dst += olen;
			len -= olen;
		}
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
		/*
		 * Do the mbedtls_cipher_reset(), mbedtls_cipher_update(),
		 * mbedtls_cipher_finish() sequence to catch and report
		 * partial blocks early.
		 */
		lmd_res = mbedtls_cipher_reset(ctx);
		if (lmd_res != 0) {
			FMSG("mbedtls_cipher_reset failed, res is 0x%x",
			     -lmd_res);
			return get_tee_result(lmd_res);
		}

		lmd_res = mbedtls_cipher_update(ctx, data, len, dst, &olen);
		if (lmd_res != 0) {
			FMSG("update failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
		lmd_res = mbedtls_cipher_finish(ctx, dst + olen, &finish_olen);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		lmd_res = mbedtls_cipher_update(ctx, data, len, dst, &olen);
		if (lmd_res != 0) {
			FMSG("update failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
		/*
		 * Finish any partial block as the caller expects all the
		 * input to be returned as encrypted output.
		 */
		lmd_res = mbedtls_cipher_finish(ctx, dst + olen, &finish_olen);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (lmd_res != 0) {
		FMSG("mbedtls cipher update failed, res is 0x%x", -lmd_res);
		return get_tee_result(lmd_res);
	}

	return TEE_SUCCESS;
}

void crypto_cipher_final(void *ctx __unused, uint32_t algo __unused)
{
}
#endif /* _CFG_CRYPTO_WITH_CIPHER */

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/
#if defined(_CFG_CRYPTO_WITH_MAC)
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
		*size = sizeof(mbedtls_md_context_t);
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_mac_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	const mbedtls_md_info_t *md_info __maybe_unused;
	int lmd_res __maybe_unused;
	const mbedtls_cipher_info_t *cipher_info __maybe_unused;
	TEE_Result res = TEE_SUCCESS;
	size_t ctx_size;
	void *ctx;

	res = mac_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		md_info = get_hash_info(TEE_ALG_HASH_ALGO(
					TEE_ALG_GET_MAIN_ALG(algo)));
		if (!md_info) {
			res =  TEE_ERROR_NOT_SUPPORTED;
			goto err;
		}

		mbedtls_md_init(ctx);
		lmd_res = mbedtls_md_setup(ctx, md_info, 1);
		if (lmd_res != 0) {
			FMSG("md setup failed, res is 0x%x", -lmd_res);
			res = get_tee_result(lmd_res);
			goto err;
		}
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		/*
		 * Use a default key length for getting 'cipher_info' to do
		 * setup, and the 'cipher_info' needed be re-set after get
		 * really key length. It is safe for 'mbedtls_cipher_base_t'
		 * (used for allocate cipher context) are same for different
		 * key length.
		 */
		cipher_info = get_cipher_info(TEE_ALG_AES_ECB_NOPAD, 128);
		if (!cipher_info) {
			res = TEE_ERROR_NOT_SUPPORTED;
			goto err;
		}
		mbedtls_cipher_init(ctx);
		lmd_res = mbedtls_cipher_setup(ctx, cipher_info);
		if (lmd_res != 0) {
			FMSG("cipher setup failed, res is 0x%x", -lmd_res);
			res = get_tee_result(lmd_res);
			goto err;
		}
		lmd_res = mbedtls_cipher_cmac_setup(ctx);
		if (lmd_res != 0) {
			FMSG("cmac setup failed, res is 0x%x", -lmd_res);
			res = get_tee_result(lmd_res);
			goto err;
		}
		break;
#endif
	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	*ctx_ret = ctx;
	return TEE_SUCCESS;
err:
	free(ctx);
	return res;
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

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		mbedtls_md_free(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		mbedtls_cipher_free(ctx);
		break;
#endif
	default:
		break;
	}
	free(ctx);
}

void crypto_mac_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	int lmd_res __maybe_unused;

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		lmd_res = mbedtls_md_clone(dst_ctx, src_ctx);
		if (lmd_res != 0) {
			FMSG("hmac clone failed, res is 0x%x", -lmd_res);
			panic();
		}
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		break;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		lmd_res = mbedtls_cipher_clone(dst_ctx, src_ctx);
		if (lmd_res != 0) {
			FMSG("cmac clone failed, res is 0x%x", -lmd_res);
			panic();
		}
		break;
#endif
	default:
		break;
	}
}

TEE_Result crypto_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len)
{
	int lmd_res __maybe_unused;
	const mbedtls_cipher_info_t *cipher_info __maybe_unused;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		lmd_res = mbedtls_md_hmac_reset(ctx);
		if (lmd_res != 0) {
			FMSG("hmac starts failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
		lmd_res = mbedtls_md_hmac_starts(ctx, key, len);
		if (lmd_res != 0) {
			FMSG("hmac starts failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		/* Re-set the cipher info according the really key length. */
		cipher_info = get_cipher_info(TEE_ALG_AES_ECB_NOPAD, len * 8);
		if (!cipher_info)
			return TEE_ERROR_NOT_SUPPORTED;

		lmd_res = mbedtls_cipher_setup_info(ctx, cipher_info);
		if (lmd_res != 0) {
			FMSG("setup info failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}

		lmd_res = mbedtls_cipher_cmac_reset(ctx);
		if (lmd_res != 0) {
			FMSG("cmac reset failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}

		lmd_res = mbedtls_cipher_cmac_starts(ctx, key, len * 8);
		if (lmd_res != 0) {
			FMSG("cmac starts failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
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
	int lmd_res __maybe_unused;

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
		lmd_res = mbedtls_md_hmac_update(ctx, data, len);
		if (lmd_res != 0) {
			FMSG("hmac update failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		lmd_res = mbedtls_cipher_cmac_update(ctx, data, len);
		if (lmd_res != 0) {
			FMSG("cmac update failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
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
	int lmd_res __maybe_unused;
	size_t block_size __maybe_unused;
	mbedtls_md_context_t *md_ctx __maybe_unused;

	switch (algo) {
#if defined(CFG_CRYPTO_HMAC)
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		md_ctx = (mbedtls_md_context_t *)ctx;
		block_size = mbedtls_md_get_size(md_ctx->md_info);
		if (block_size > digest_len)
			return TEE_ERROR_SHORT_BUFFER;
		lmd_res = mbedtls_md_hmac_finish(md_ctx, digest);
		if (lmd_res != 0) {
			FMSG("hmac finish failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
		break;
#endif
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#if defined(CFG_CRYPTO_CMAC)
	case TEE_ALG_AES_CMAC:
		block_size = mbedtls_cipher_get_block_size(ctx);
		if (block_size > digest_len)
			return TEE_ERROR_SHORT_BUFFER;

		lmd_res = mbedtls_cipher_cmac_finish(ctx, digest);
		if (lmd_res != 0) {
			FMSG("cmac finish failed, res is 0x%x", -lmd_res);
			return get_tee_result(lmd_res);
		}
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
#define MBEDTLS_CCM_ENCRYPT		0
#define MBEDTLS_CCM_DECRYPT		1
#define TEE_CCM_KEY_MAX_LENGTH		32
#define TEE_CCM_NONCE_MAX_LENGTH	13
#define TEE_CCM_TAG_MAX_LENGTH		16

#if defined(CFG_CRYPTO_CCM)
struct tee_ccm_state {
	mbedtls_ccm_context ctx;	/* the ccm state as defined by LMD */
	size_t tag_len;			/* tag length */
	unsigned char iv[16];		/* IV */
	size_t iv_size;			/*
					 * IV size in bytes (for ciphers with
					 * variable-length IVs)
					 */
	bool iv_flag;			/* whether IV has been set */
	unsigned char *aad;		/* AAD */
	size_t aad_len;			/* AAD size in bytes */
	size_t aad_totallen;		/*total aad length */
	size_t payload_len;		/*src_len*/
};

TEE_Result crypto_aes_ccm_alloc_ctx(void **ctx_ret)
{
	int lmd_res = 0;
	struct tee_ccm_state *ccm;
	const mbedtls_cipher_info_t *cipher_info = NULL;

	cipher_info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES,
						      128, MBEDTLS_MODE_ECB);
	if (!cipher_info)
		return TEE_ERROR_NOT_SUPPORTED;

	assert(cipher_info->block_size == 16);

	ccm = calloc(1, sizeof(*ccm));
	if (!ccm)
		return TEE_ERROR_OUT_OF_MEMORY;

	lmd_res = mbedtls_cipher_setup(&ccm->ctx.cipher_ctx, cipher_info);
	if (lmd_res != 0) {
		crypto_aes_ccm_free_ctx(ccm);
		FMSG("cipher setup failed, res is 0x%x", -lmd_res);
		return get_tee_result(lmd_res);
	}

	*ctx_ret = ccm;
	return TEE_SUCCESS;
}

void crypto_aes_ccm_free_ctx(void *ctx)
{
	struct tee_ccm_state *ccm = ctx;

	if (ccm) {
		mbedtls_ccm_free(&ccm->ctx);
		free(ccm->aad);
	}
	free(ccm);
}

void crypto_aes_ccm_copy_state(void *dst_ctx, void *src_ctx)
{
	int lmd_res = 0;
	struct tee_ccm_state *dst_ccm = dst_ctx;
	struct tee_ccm_state *src_ccm = src_ctx;

	/* If the dest aad length is less than src's? */
	if (dst_ccm->aad && (dst_ccm->aad_totallen < src_ccm->aad_totallen)) {
		free(dst_ccm->aad);
		dst_ccm->aad = NULL;
	}

	dst_ccm->aad_len = src_ccm->aad_len;
	dst_ccm->tag_len = src_ccm->tag_len;
	dst_ccm->iv_size = src_ccm->iv_size;
	dst_ccm->payload_len = src_ccm->payload_len;
	dst_ccm->iv_flag = src_ccm->iv_flag;
	dst_ccm->aad_totallen = src_ccm->aad_totallen;
	memcpy(dst_ccm->iv, src_ccm->iv, sizeof(src_ccm->iv));
	if (!dst_ccm->aad) {
		dst_ccm->aad = calloc(1, dst_ccm->aad_totallen);
		if (!dst_ccm->aad)
			panic();
	}
	memcpy(dst_ccm->aad, src_ccm->aad, src_ccm->aad_totallen);

	lmd_res = mbedtls_ccm_clone(&dst_ccm->ctx, &src_ccm->ctx);
	if (lmd_res != 0) {
		FMSG("ccm clone failed, res is 0x%x", -lmd_res);
		panic();
	}
}

TEE_Result crypto_aes_ccm_init(void *ctx, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len)
{
	int lmd_res = 0;
	struct tee_ccm_state *ccm = ctx;
	const mbedtls_cipher_info_t *cipher_info = NULL;
	int ret;

	/* Check the key length */
	if (!key || (key_len > TEE_CCM_KEY_MAX_LENGTH))
		return TEE_ERROR_BAD_PARAMETERS;

	/* check the nonce */
	if (nonce_len > TEE_CCM_NONCE_MAX_LENGTH)
		return TEE_ERROR_BAD_PARAMETERS;

	/* check the tag len */
	if ((tag_len < 4) || (tag_len > TEE_CCM_TAG_MAX_LENGTH) ||
	    (tag_len % 2 != 0)) {
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (aad_len > 0xFF00)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher_info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES,
						      key_len * 8,
						      MBEDTLS_MODE_ECB);
	if (!cipher_info)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(cipher_info->block_size == 16);

	lmd_res = mbedtls_cipher_setup_info(&ccm->ctx.cipher_ctx, cipher_info);
	if (lmd_res != 0) {
		ret = get_tee_result(lmd_res);
		goto err;
	}

	lmd_res = mbedtls_cipher_setkey(&ccm->ctx.cipher_ctx, key,
					key_len * 8, MBEDTLS_ENCRYPT);
	if (lmd_res != 0) {
		ret = get_tee_result(lmd_res);
		goto err;
	}

	ccm->tag_len = tag_len;
	ccm->payload_len = payload_len;
	ccm->aad_totallen = aad_len;
	ccm->iv_size = nonce_len;
	memcpy(ccm->iv, nonce, nonce_len);

	if ((aad_len != 0) && !ccm->aad) {
		ccm->aad = calloc(1, aad_len);
		if (!ccm->aad) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}
	ccm->ctx.mode = (mode == TEE_MODE_ENCRYPT ?
			 MBEDTLS_CCM_ENCRYPT : MBEDTLS_CCM_DECRYPT);
	return TEE_SUCCESS;
err:
	if (ccm->aad)
		free(ccm->aad);
	return ret;
}

TEE_Result crypto_aes_ccm_update_aad(void *ctx, const uint8_t *data, size_t len)
{
	int lmd_res = 0;
	struct tee_ccm_state *ccm = ctx;
	const uint8_t *temp_data = data;

	if (len + ccm->aad_len > ccm->aad_totallen)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len != ccm->aad_totallen) {
		memcpy(ccm->aad + ccm->aad_len, data, len);
		ccm->aad_len += len;
	}

	if (ccm->aad_len == ccm->aad_totallen)
		temp_data = ccm->aad;

	if (len == ccm->aad_totallen || ccm->aad_len == ccm->aad_totallen) {
		lmd_res = mbedtls_ccm_starts(&ccm->ctx, ccm->ctx.mode,
					     ccm->payload_len, ccm->iv,
					     ccm->iv_size, temp_data,
					     ccm->aad_totallen, ccm->tag_len);
		if (lmd_res != 0)
			return TEE_ERROR_BAD_STATE;
		ccm->iv_flag = true;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_update_payload(void *ctx,
					 TEE_OperationMode mode __unused,
					 const uint8_t *src_data,
					 size_t len, uint8_t *dst_data)
{
	int lmd_res = 0;
	struct tee_ccm_state *ccm = ctx;

	if (!ccm->iv_flag)
		crypto_aes_ccm_update_aad(ccm, NULL, 0);

	/* process the data */
	lmd_res = mbedtls_ccm_update(&ccm->ctx, len, src_data, dst_data);
	if (lmd_res != 0)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_enc_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    uint8_t *dst_tag, size_t *dst_tag_len)
{
	TEE_Result res;
	struct tee_ccm_state *ccm = ctx;

	res = crypto_aes_ccm_update_payload(ccm, TEE_MODE_ENCRYPT,
					    src_data, len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Check the tag length */
	if (*dst_tag_len < ccm->tag_len) {
		*dst_tag_len = ccm->tag_len;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_tag_len = ccm->tag_len;

	/* Compute the tag */
	if (mbedtls_ccm_finish(&ccm->ctx, dst_tag, *dst_tag_len) != 0)
		return TEE_ERROR_BAD_STATE;
	return TEE_SUCCESS;
}

TEE_Result crypto_aes_ccm_dec_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    const uint8_t *tag, size_t tag_len)
{
	TEE_Result res;
	struct tee_ccm_state *ccm = ctx;
	uint8_t dst_tag[TEE_CCM_TAG_MAX_LENGTH];
	unsigned long lmd_tag_len = tag_len;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_CCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	res = crypto_aes_ccm_update_payload(ccm, TEE_MODE_DECRYPT,
					    src_data, len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Finalize the authentication */
	if (mbedtls_ccm_finish(&ccm->ctx, dst_tag, lmd_tag_len) != 0)
		return TEE_ERROR_BAD_STATE;

	if (buf_compare_ct(dst_tag, tag, tag_len) != 0)
		return TEE_ERROR_MAC_INVALID;
	return TEE_SUCCESS;
}

void crypto_aes_ccm_final(void *ctx)
{
	struct tee_ccm_state *ccm = ctx;

	ccm->aad_len = 0;
	ccm->tag_len = 0;
	ccm->iv_size = 0;
	ccm->payload_len = 0;
	ccm->aad_totallen = 0;
	ccm->iv_flag = 0;
	memset(ccm->iv, 0, sizeof(ccm->iv));
	if (ccm->aad)
		memset(ccm->aad, 0, ccm->aad_totallen);
	mbedtls_cipher_reset(&ccm->ctx.cipher_ctx);
}
#endif /*CFG_CRYPTO_CCM*/

#if defined(CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB)
TEE_Result crypto_aes_gcm_alloc_ctx(void **ctx_ret __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_gcm_free_ctx(void *ctx __unused)
{
	if (ctx)
		assert(0);
}

void crypto_aes_gcm_copy_state(void *dst_ctx __unused, void *src_ctx __unused)
{
	assert(0);
}

TEE_Result crypto_aes_gcm_init(void *ctx __unused,
			       TEE_OperationMode mode __unused,
			       const uint8_t *key __unused,
			       size_t key_len __unused,
			       const uint8_t *nonce __unused,
			       size_t nonce_len __unused,
			       size_t tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_update_aad(void *ctx __unused,
				const uint8_t *data __unused,
				size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_update_payload(void *ctx __unused,
					 TEE_OperationMode mode __unused,
					 const uint8_t *src_data __unused,
					 size_t len __unused,
					 uint8_t *dst_data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_enc_final(void *ctx __unused,
				    const uint8_t *src_data __unused,
				    size_t len __unused,
				    uint8_t *dst_data __unused,
				    uint8_t *dst_tag __unused,
				    size_t *dst_tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_gcm_dec_final(void *ctx __unused,
				    const uint8_t *src_data __unused,
				    size_t len __unused,
				    uint8_t *dst_data __unused,
				    const uint8_t *tag __unused,
				    size_t tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_gcm_final(void *ctx __unused)
{
	if (ctx)
		assert(0);
}
#endif /*CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB*/

TEE_Result crypto_init(void)
{
	return TEE_SUCCESS;
}

#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash,
		const uint8_t *data, size_t data_size)
{
	mbedtls_sha256_context hs;
	uint8_t digest[TEE_SHA256_HASH_SIZE];

	mbedtls_sha256_init(&hs);
	mbedtls_sha256_starts(&hs, 0);
	mbedtls_sha256_update(&hs, data, data_size);
	mbedtls_sha256_finish(&hs, digest);
	mbedtls_sha256_free(&hs);

	if (buf_compare_ct(digest, hash, sizeof(digest)) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
#endif

TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				     void *enc_key, size_t enc_keylen,
				     unsigned int *rounds)
{
	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);
	if (mbedtls_aes_setkey_enc(&ctx, key, key_len * 8) != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (enc_keylen > sizeof(ctx.buf))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(enc_key, ctx.buf, enc_keylen);
	*rounds = ctx.nr;
	mbedtls_aes_free(&ctx);
	return TEE_SUCCESS;
}

void crypto_aes_enc_block(const void *enc_key, size_t enc_keylen,
			  unsigned int rounds, const void *src, void *dst)
{
	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);
	if (enc_keylen > sizeof(ctx.buf))
		panic();
	memcpy(ctx.buf, enc_key, enc_keylen);
	ctx.rk = ctx.buf;
	ctx.nr = rounds;
	mbedtls_aes_encrypt(&ctx, src, dst);
	mbedtls_aes_free(&ctx);
}
