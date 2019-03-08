// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/aes-ccm.h>
#include <crypto/aes-gcm.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string.h>

TEE_Result crypto_hash_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result res = TEE_SUCCESS;
	struct crypto_hash_ctx *c = NULL;

	switch (algo) {
	case TEE_ALG_MD5:
		res = crypto_md5_alloc_ctx(&c);
		break;
	case TEE_ALG_SHA1:
		res = crypto_sha1_alloc_ctx(&c);
		break;
	case TEE_ALG_SHA224:
		res = crypto_sha224_alloc_ctx(&c);
		break;
	case TEE_ALG_SHA256:
		res = crypto_sha256_alloc_ctx(&c);
		break;
	case TEE_ALG_SHA384:
		res = crypto_sha384_alloc_ctx(&c);
		break;
	case TEE_ALG_SHA512:
		res = crypto_sha512_alloc_ctx(&c);
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!res)
		*ctx = c;

	return res;
}

static const struct crypto_hash_ops *hash_ops(void *ctx)
{
	struct crypto_hash_ctx *c = ctx;

	assert(c && c->ops);

	return c->ops;
}

void crypto_hash_free_ctx(void *ctx, uint32_t algo __unused)
{
	if (ctx)
		hash_ops(ctx)->free_ctx(ctx);
}

void crypto_hash_copy_state(void *dst_ctx, void *src_ctx,
			    uint32_t algo __unused)
{
	hash_ops(dst_ctx)->copy_state(dst_ctx, src_ctx);
}

TEE_Result crypto_hash_init(void *ctx, uint32_t algo __unused)
{
	return hash_ops(ctx)->init(ctx);
}

TEE_Result crypto_hash_update(void *ctx, uint32_t algo __unused,
			      const uint8_t *data, size_t len)
{
	return hash_ops(ctx)->update(ctx, data, len);
}

TEE_Result crypto_hash_final(void *ctx, uint32_t algo __unused,
			     uint8_t *digest, size_t len)
{
	return hash_ops(ctx)->final(ctx, digest, len);
}

#if !defined(_CFG_CRYPTO_WITH_CIPHER)
TEE_Result crypto_cipher_alloc_ctx(void **ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_cipher_free_ctx(void *ctx, uint32_t algo __unused)
{
	if (ctx)
		assert(0);
}

void crypto_cipher_copy_state(void *dst_ctx __unused, void *src_ctx __unused,
			      uint32_t algo __unused)
{
	assert(0);
}

TEE_Result crypto_cipher_init(void *ctx __unused, uint32_t algo __unused,
			      TEE_OperationMode mode __unused,
			      const uint8_t *key1 __unused,
			      size_t key1_len __unused,
			      const uint8_t *key2 __unused,
			      size_t key2_len __unused,
			      const uint8_t *iv __unused,
			      size_t iv_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_cipher_update(void *ctx __unused, uint32_t algo __unused,
				TEE_OperationMode mode __unused,
				bool last_block __unused,
				const uint8_t *data __unused,
				size_t len __unused, uint8_t *dst __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_cipher_final(void *ctx __unused, uint32_t algo __unused)
{
}

TEE_Result crypto_cipher_get_block_size(uint32_t algo __unused,
					size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*_CFG_CRYPTO_WITH_CIPHER*/

#if !defined(_CFG_CRYPTO_WITH_MAC)
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
	assert(0);
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

TEE_Result crypto_authenc_alloc_ctx(void **ctx, uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		return crypto_aes_ccm_alloc_ctx(ctx);
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		return crypto_aes_gcm_alloc_ctx(ctx);
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

void crypto_authenc_free_ctx(void *ctx, uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		crypto_aes_ccm_free_ctx(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		crypto_aes_gcm_free_ctx(ctx);
		break;
#endif
	default:
		if (ctx)
			assert(0);
	}
}

void crypto_authenc_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		crypto_aes_ccm_copy_state(dst_ctx, src_ctx);
		break;
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		crypto_aes_gcm_copy_state(dst_ctx, src_ctx);
		break;
#endif
	default:
		assert(0);
	}
}

TEE_Result crypto_authenc_init(void *ctx __maybe_unused,
			       uint32_t algo __maybe_unused,
			       TEE_OperationMode mode __maybe_unused,
			       const uint8_t *key __maybe_unused,
			       size_t key_len __maybe_unused,
			       const uint8_t *nonce __maybe_unused,
			       size_t nonce_len __maybe_unused,
			       size_t tag_len __maybe_unused,
			       size_t aad_len __maybe_unused,
			       size_t payload_len __maybe_unused)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		return crypto_aes_ccm_init(ctx, mode, key, key_len, nonce,
					   nonce_len, tag_len, aad_len,
					   payload_len);
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		return crypto_aes_gcm_init(ctx, mode, key, key_len, nonce,
					   nonce_len, tag_len);
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

TEE_Result crypto_authenc_update_aad(void *ctx __maybe_unused,
				     uint32_t algo __maybe_unused,
				     TEE_OperationMode mode __unused,
				     const uint8_t *data __maybe_unused,
				     size_t len __maybe_unused)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		return crypto_aes_ccm_update_aad(ctx, data, len);
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		return crypto_aes_gcm_update_aad(ctx, data, len);
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

TEE_Result crypto_authenc_update_payload(void *ctx __maybe_unused,
					 uint32_t algo __maybe_unused,
					 TEE_OperationMode mode __maybe_unused,
					 const uint8_t *src_data __maybe_unused,
					 size_t src_len __maybe_unused,
					 uint8_t *dst_data __maybe_unused,
					 size_t *dst_len __maybe_unused)
{
	size_t dl = *dst_len;

	*dst_len = src_len;
	if (dl < src_len)
		return TEE_ERROR_SHORT_BUFFER;

	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		return crypto_aes_ccm_update_payload(ctx, mode, src_data,
						     src_len, dst_data);
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		return crypto_aes_gcm_update_payload(ctx, mode, src_data,
						     src_len, dst_data);
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

TEE_Result crypto_authenc_enc_final(void *ctx __maybe_unused,
				    uint32_t algo __maybe_unused,
				    const uint8_t *src_data __maybe_unused,
				    size_t src_len __maybe_unused,
				    uint8_t *dst_data __maybe_unused,
				    size_t *dst_len __maybe_unused,
				    uint8_t *dst_tag __maybe_unused,
				    size_t *dst_tag_len __maybe_unused)
{
	size_t dl = *dst_len;

	*dst_len = src_len;
	if (dl < src_len)
		return TEE_ERROR_SHORT_BUFFER;

	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		return crypto_aes_ccm_enc_final(ctx, src_data, src_len,
						dst_data, dst_tag, dst_tag_len);
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		return crypto_aes_gcm_enc_final(ctx, src_data, src_len,
						dst_data, dst_tag, dst_tag_len);
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

TEE_Result crypto_authenc_dec_final(void *ctx __maybe_unused,
				    uint32_t algo __maybe_unused,
				    const uint8_t *src_data __maybe_unused,
				    size_t src_len __maybe_unused,
				    uint8_t *dst_data __maybe_unused,
				    size_t *dst_len __maybe_unused,
				    const uint8_t *tag __maybe_unused,
				    size_t tag_len __maybe_unused)
{
	size_t dl = *dst_len;

	*dst_len = src_len;
	if (dl < src_len)
		return TEE_ERROR_SHORT_BUFFER;

	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		return crypto_aes_ccm_dec_final(ctx, src_data, src_len,
						dst_data, tag, tag_len);
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		return crypto_aes_gcm_dec_final(ctx, src_data, src_len,
						dst_data, tag, tag_len);
#endif
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

void crypto_authenc_final(void *ctx __maybe_unused,
			  uint32_t algo __maybe_unused)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CCM)
	case TEE_ALG_AES_CCM:
		crypto_aes_ccm_final(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_GCM)
	case TEE_ALG_AES_GCM:
		crypto_aes_gcm_final(ctx);
		break;
#endif
	default:
		break;
	}
}

#if !defined(_CFG_CRYPTO_WITH_ACIPHER)
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

/*
 * crypto_bignum_allocate() and crypto_bignum_bin2bn() failing should be
 * enough to guarantee that the functions calling this function aren't
 * called, but just in case add a panic() here to avoid unexpected
 * behavoir.
 */
static void bignum_cant_happen(void)
{
	volatile bool b = true;

	/* Avoid warning about function does not return */
	if (b)
		panic();
}

void crypto_bignum_bn2bin(const struct bignum *from __unused,
			  uint8_t *to __unused)
{
	bignum_cant_happen();
}

void crypto_bignum_copy(struct bignum *to __unused,
			const struct bignum *from __unused)
{
	bignum_cant_happen();
}

void crypto_bignum_free(struct bignum *a)
{
	if (a)
		panic();
}

void crypto_bignum_clear(struct bignum *a __unused)
{
	bignum_cant_happen();
}

/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *a __unused,
			      struct bignum *b __unused)
{
	bignum_cant_happen();
	return -1;
}
#endif /*!_CFG_CRYPTO_WITH_ACIPHER*/

#if !defined(CFG_CRYPTO_RSA) || !defined(_CFG_CRYPTO_WITH_ACIPHER)
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
#endif /*!CFG_CRYPTO_RSA || !_CFG_CRYPTO_WITH_ACIPHER*/

#if !defined(CFG_CRYPTO_DSA) || !defined(_CFG_CRYPTO_WITH_ACIPHER)
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
#endif /*!CFG_CRYPTO_DSA || !_CFG_CRYPTO_WITH_ACIPHER*/

#if !defined(CFG_CRYPTO_DH) || !defined(_CFG_CRYPTO_WITH_ACIPHER)
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
#endif /*!CFG_CRYPTO_DH || !_CFG_CRYPTO_WITH_ACIPHER*/

#if !defined(CFG_CRYPTO_ECC) || !defined(_CFG_CRYPTO_WITH_ACIPHER)
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
#endif /*!CFG_CRYPTO_ECC || !_CFG_CRYPTO_WITH_ACIPHER*/
