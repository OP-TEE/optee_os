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
#include <stdlib.h>

/******************************************************************************
 * Message digest functions
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_HASH)
TEE_Result crypto_hash_get_ctx_size(uint32_t algo, size_t *size)
{

	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_hash_init(void *ctx, uint32_t algo)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_hash_update(void *ctx, uint32_t algo,
				      const uint8_t *data, size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_hash_final(void *ctx, uint32_t algo, uint8_t *digest,
			     size_t len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
	return TEE_ERROR_NOT_IMPLEMENTED;
}


#if defined(CFG_CRYPTO_SHA256)
TEE_Result hash_sha256_check(const uint8_t *hash, const uint8_t *data,
		size_t data_size)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
