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
#endif /*
	* defined(_CFG_CRYPTO_WITH_HASH) ||
	* defined(CFG_CRYPTO_RSA) || defined(_CFG_CRYPTO_WITH_MAC)
	*/

#if defined(_CFG_CRYPTO_WITH_CIPHER) || defined(_CFG_CRYPTO_WITH_MAC) || \
	defined(_CFG_CRYPTO_WITH_AUTHENC)
/*
 * Get the Mbedtls chipher info given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - NULL in case of error
 */
static const mbedtls_cipher_info_t
		*tee_algo_to_mbedtls_cipher_info(uint32_t algo,
						size_t key_len)
{
	/* Only support key_length is 128 bits of AES in Optee_os */
	switch (algo) {
#if defined(CFG_CRYPTO_AES)
	case TEE_ALG_AES_ECB_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_string("AES-128-ECB");
		else if (key_len == 192)
			return mbedtls_cipher_info_from_string("AES-192-ECB");
		else if (key_len == 256)
			return mbedtls_cipher_info_from_string("AES-256-ECB");
		else
			return NULL;
	case TEE_ALG_AES_CBC_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_string("AES-128-CBC");
		else if (key_len == 192)
			return mbedtls_cipher_info_from_string("AES-192-CBC");
		else if (key_len == 256)
			return mbedtls_cipher_info_from_string("AES-256-CBC");
		else
			return NULL;
	case TEE_ALG_AES_CTR:
		if (key_len == 128)
			return mbedtls_cipher_info_from_string("AES-128-CTR");
		else if (key_len == 192)
			return mbedtls_cipher_info_from_string("AES-192-CTR");
		else if (key_len == 256)
			return mbedtls_cipher_info_from_string("AES-256-CTR");
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
			return mbedtls_cipher_info_from_string("DES-ECB");
		else
			return NULL;
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		return NULL;
	case TEE_ALG_DES_CBC_NOPAD:
		if (key_len == 64)
			return mbedtls_cipher_info_from_string("DES-CBC");
		else
			return NULL;
	case TEE_ALG_DES3_ECB_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_string("DES-EDE-ECB");
		else if (key_len == 192)
			return mbedtls_cipher_info_from_string("DES-EDE3-ECB");
		else
			return NULL;
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		return NULL;
	case TEE_ALG_DES3_CBC_NOPAD:
		if (key_len == 128)
			return mbedtls_cipher_info_from_string("DES-EDE-CBC");
		else if (key_len == 192)
			return mbedtls_cipher_info_from_string("DES-EDE3-CBC");
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

size_t crypto_bignum_num_bytes(struct bignum *a)
{
	return 0;
}

size_t crypto_bignum_num_bits(struct bignum *a)
{
	return 0;
}

int32_t crypto_bignum_compare(struct bignum *a, struct bignum *b)
{
	return 0;
}

void crypto_bignum_bn2bin(const struct bignum *from, uint8_t *to)
{
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from, size_t fromsize,
			 struct bignum *to)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_bignum_copy(struct bignum *to, const struct bignum *from)
{
}

struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	return NULL;
}

void crypto_bignum_free(struct bignum *s)
{
	free(s);
}

void crypto_bignum_clear(struct bignum *s)
{
}

#if defined(CFG_CRYPTO_RSA)

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s,
					       size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *src, size_t src_len,
					   uint8_t *dst, size_t *dst_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo, struct rsa_keypair *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *label, size_t label_len,
					const uint8_t *src, size_t src_len,
					uint8_t *dst, size_t *dst_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo, struct rsa_keypair *key,
				      int salt_len, const uint8_t *msg,
				      size_t msg_len, uint8_t *sig,
				      size_t *sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len, const uint8_t *msg,
					size_t msg_len, const uint8_t *sig,
					size_t sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
					   size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key, struct bignum *q,
				     size_t xbits)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *public_key,
					   struct bignum *secret)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

#endif /* CFG_CRYPTO_DH */

#if defined(CFG_CRYPTO_ECC)

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
					    size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
					       size_t key_size_bits __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s)
{
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_ECC */

#endif /* _CFG_CRYPTO_WITH_ACIPHER */

/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_CIPHER)

TEE_Result crypto_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
#endif
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
#if defined(CFG_CRYPTO_DES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
#endif
		*size = sizeof(mbedtls_cipher_context_t);
		break;
#endif
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		return TEE_ERROR_NOT_SUPPORTED;
	break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		return TEE_ERROR_NOT_SUPPORTED;
#endif
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_cipher_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2 __maybe_unused,
			      size_t key2_len __maybe_unused,
			      const uint8_t *iv __maybe_unused,
			      size_t iv_len __maybe_unused)
{
	const mbedtls_cipher_info_t *cipher_info = NULL;
	int lmd_res;

	if (ctx == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_cipher_init(ctx);

	cipher_info = tee_algo_to_mbedtls_cipher_info(algo,
			key1_len * 8);
	if (cipher_info == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	lmd_res = mbedtls_cipher_setup(ctx, cipher_info);
	if (lmd_res != 0) {
		EMSG("mbedtls_cipher_setup failed, res is 0x%x\n", -lmd_res);
		return TEE_ERROR_BAD_STATE;
	}

	lmd_res = mbedtls_cipher_setkey(ctx, key1, key1_len * 8,
				mode == TEE_MODE_ENCRYPT ?
				MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
	if (lmd_res != 0) {
		EMSG("setkey failed, res is 0x%x\n", -lmd_res);
		return TEE_ERROR_BAD_STATE;
	}

	if (iv != NULL) {
		lmd_res = mbedtls_cipher_set_iv(ctx, iv, iv_len);
		if (lmd_res != 0) {
			EMSG("set iv failed, res is 0x%x\n", -lmd_res);
			return TEE_ERROR_BAD_STATE;
		}
	}

	lmd_res = mbedtls_cipher_reset(ctx);
	if (lmd_res != 0) {
		EMSG("mbedtls_cipher_reset failed, res is 0x%x\n", -lmd_res);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				bool last_block __maybe_unused,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	int lmd_res;
	size_t olen;
	size_t finish_olen;
#if defined(CFG_CRYPTO_ECB)
	size_t blk_size;
#endif
	if (ctx == NULL)
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
			lmd_res = mbedtls_cipher_update(ctx, data,
					blk_size, dst, &olen);
			if (lmd_res != 0) {
				EMSG("update failed, res is 0x%x\n", -lmd_res);
				return TEE_ERROR_BAD_STATE;
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
		lmd_res = mbedtls_cipher_reset(ctx);
		if (lmd_res != 0) {
			EMSG("mbedtls_cipher_reset failed, res is 0x%x\n", -lmd_res);
			return TEE_ERROR_BAD_STATE;
		}

		lmd_res = mbedtls_cipher_update(ctx, data, len, dst, &olen);
		if (lmd_res != 0) {
			EMSG("update failed, res is 0x%x\n", -lmd_res);
			return TEE_ERROR_BAD_STATE;
		}
		lmd_res = mbedtls_cipher_finish(ctx, dst + olen, &finish_olen);
		break;
#endif
#if defined(CFG_CRYPTO_CTR)
	case TEE_ALG_AES_CTR:
		lmd_res = mbedtls_cipher_update(ctx, data, len, dst, &olen);
		if (lmd_res != 0) {
			EMSG("update failed, res is 0x%x\n", -lmd_res);
			return TEE_ERROR_BAD_STATE;
		}

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
		EMSG("mbedtls_cipher_update failed, res is 0x%x\n",
				-lmd_res);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
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
