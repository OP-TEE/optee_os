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
#if defined(CFG_CRYPTO_DES)
#include "mbedtls/des.h"
#endif
#if defined(_CFG_CRYPTO_WITH_CIPHER)
#include "mbedtls/cipher.h"
#include "mbedtls/cipher_internal.h"
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

#if defined(CFG_CRYPTO_AES)
/* Translate mbedtls result to TEE result */
static TEE_Result get_tee_result(int lmd_res)
{
	switch (lmd_res) {
#if defined(CFG_CRYPTO_AES)
	case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
		return TEE_ERROR_NOT_SUPPORTED;
	case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
		return TEE_ERROR_BAD_PARAMETERS;
	case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
		return TEE_ERROR_OUT_OF_MEMORY;
#endif
	case 0:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_STATE;
	}
}
#endif /* defined(CFG_CRYPTO_AES) */

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
struct bignum *crypto_bignum_allocate(size_t size_bits __unused)
{
	return NULL;
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from __unused,
				size_t fromsize __unused,
				struct bignum *to __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

size_t crypto_bignum_num_bytes(struct bignum *a __unused)
{
	return 0;
}

size_t crypto_bignum_num_bits(struct bignum *a __unused)
{
	return 0;
}

void crypto_bignum_bn2bin(const struct bignum *from __unused,
			  uint8_t *to __unused)
{
}

void crypto_bignum_copy(struct bignum *to __unused,
			const struct bignum *from __unused)
{
}

void crypto_bignum_free(struct bignum *a)
{
	if (a)
		panic();
}

void crypto_bignum_clear(struct bignum *a __unused)
{
}

/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *a __unused,
			      struct bignum *b __unused)
{
	return -1;
}


#if defined(CFG_CRYPTO_RSA)
TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s __unused)
{
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key __unused,
				      size_t key_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key __unused,
					   const uint8_t *src __unused,
					   size_t src_len __unused,
					   uint8_t *dst __unused,
					   size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key __unused,
					   const uint8_t *src __unused,
					   size_t src_len __unused,
					   uint8_t *dst __unused,
					   size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo __unused,
					struct rsa_keypair *key __unused,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src __unused,
					size_t src_len __unused,
					uint8_t *dst __unused,
					size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo __unused,
					struct rsa_public_key *key __unused,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src __unused,
					size_t src_len __unused,
					uint8_t *dst __unused,
					size_t *dst_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo __unused,
				      struct rsa_keypair *key __unused,
				      int salt_len __unused,
				      const uint8_t *msg __unused,
				      size_t msg_len __unused,
				      uint8_t *sig __unused,
				      size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo __unused,
					struct rsa_public_key *key __unused,
					int salt_len __unused,
					const uint8_t *msg __unused,
					size_t msg_len __unused,
					const uint8_t *sig __unused,
					size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *s __unused,
					   size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key __unused,
				     struct bignum *q __unused,
				     size_t xbits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_dh_shared_secret(struct dh_keypair *private_key __unused,
				struct bignum *public_key __unused,
				struct bignum *secret __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_DH */

#if defined(CFG_CRYPTO_ECC)
TEE_Result
crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s __unused)
{
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo __unused,
				   struct ecc_keypair *key __unused,
				   const uint8_t *msg __unused,
				   size_t msg_len __unused,
				   uint8_t *sig __unused,
				   size_t *sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo __unused,
				     struct ecc_public_key *key __unused,
				     const uint8_t *msg __unused,
				     size_t msg_len __unused,
				     const uint8_t *sig __unused,
				     size_t sig_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key __unused,
				 struct ecc_public_key *public_key __unused,
				 void *secret __unused,
				 unsigned long *secret_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
TEE_Result crypto_mac_alloc_ctx(void **ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_mac_free_ctx(void *ctx, uint32_t algo __unused)
{
	if (ctx)
		assert(0);
}

void crypto_mac_copy_state(void *dst_ctx __unused, void *src_ctx __unused,
			   uint32_t algo __unused)
{
}

TEE_Result crypto_mac_init(void *ctx __unused, uint32_t algo __unused,
			   const uint8_t *key __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_update(void *ctx __unused, uint32_t algo __unused,
			     const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_final(void *ctx __unused, uint32_t algo __unused,
			    uint8_t *digest __unused,
			    size_t digest_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*_CFG_CRYPTO_WITH_MAC*/

/******************************************************************************
 * Authenticated encryption
 ******************************************************************************/
#if defined(CFG_CRYPTO_CCM)
TEE_Result crypto_aes_ccm_alloc_ctx(void **ctx_ret __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_ccm_free_ctx(void *ctx __unused)
{
	if (ctx)
		assert(0);
}

void crypto_aes_ccm_copy_state(void *dst_ctx __unused, void *src_ctx __unused)
{
}

TEE_Result crypto_aes_ccm_init(void *ctx __unused,
			       TEE_OperationMode mode __unused,
			       const uint8_t *key __unused,
			       size_t key_len __unused,
			       const uint8_t *nonce __unused,
			       size_t nonce_len __unused,
			       size_t tag_len __unused,
			       size_t aad_len __unused,
			       size_t payload_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_update_aad(void *ctx __unused,
			const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_update_payload(void *ctx __unused,
					 TEE_OperationMode mode __unused,
					 const uint8_t *src_data __unused,
					 size_t len __unused,
					 uint8_t *dst_data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_enc_final(void *ctx __unused,
				    const uint8_t *src_data __unused,
				    size_t len __unused,
				    uint8_t *dst_data __unused,
				    uint8_t *dst_tag __unused,
				    size_t *dst_tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_ccm_dec_final(void *ctx __unused,
				    const uint8_t *src_data __unused,
				    size_t len __unused,
				    uint8_t *dst_data __unused,
				    const uint8_t *tag __unused,
				    size_t tag_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_ccm_final(void *ctx __unused)
{
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

TEE_Result crypto_aes_expand_enc_key(const void *key __unused,
				     size_t key_len __unused,
				     void *enc_key __unused,
				     unsigned int *rounds __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_enc_block(const void *enc_key __unused,
			  unsigned int rounds __unused,
			  const void *src __unused,
			  void *dst __unused)
{
}
