/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __CRYPTO_CRYPTO_IMPL_H
#define __CRYPTO_CRYPTO_IMPL_H

#include <tee_api_types.h>

/*
 * The crypto context used by the crypto_hash_*() functions is defined by
 * struct crypto_hash_ctx.
 */
struct crypto_hash_ctx {
	const struct crypto_hash_ops *ops;
};

struct crypto_hash_ops {
	TEE_Result (*init)(struct crypto_hash_ctx *ctx);
	TEE_Result (*update)(struct crypto_hash_ctx *ctx, const uint8_t *data,
			     size_t len);
	TEE_Result (*final)(struct crypto_hash_ctx *ctx, uint8_t *digest,
			    size_t len);
	void (*free_ctx)(struct crypto_hash_ctx *ctx);
	void (*copy_state)(struct crypto_hash_ctx *dst_ctx,
			   struct crypto_hash_ctx *src_ctx);
};

#define CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(name, type) \
	static inline TEE_Result \
	crypto_##name##_alloc_ctx(struct crypto_##type##_ctx **ctx __unused) \
	{ return TEE_ERROR_NOT_IMPLEMENTED; }

#if defined(CFG_CRYPTO_MD5)
TEE_Result crypto_md5_alloc_ctx(struct crypto_hash_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(md5, hash)
#endif

#if defined(CFG_CRYPTO_SHA1)
TEE_Result crypto_sha1_alloc_ctx(struct crypto_hash_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha1, hash)
#endif

#if defined(CFG_CRYPTO_SHA224)
TEE_Result crypto_sha224_alloc_ctx(struct crypto_hash_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha224, hash)
#endif

#if defined(CFG_CRYPTO_SHA256)
TEE_Result crypto_sha256_alloc_ctx(struct crypto_hash_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha256, hash)
#endif

#if defined(CFG_CRYPTO_SHA384)
TEE_Result crypto_sha384_alloc_ctx(struct crypto_hash_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha384, hash)
#endif

#if defined(CFG_CRYPTO_SHA512)
TEE_Result crypto_sha512_alloc_ctx(struct crypto_hash_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(sha512, hash)
#endif

/*
 * The crypto context used by the crypto_mac_*() functions is defined by
 * struct crypto_mac_ctx.
 */
struct crypto_mac_ctx {
	const struct crypto_mac_ops *ops;
};

struct crypto_mac_ops {
	TEE_Result (*init)(struct crypto_mac_ctx *ctx, const uint8_t *key,
			   size_t len);
	TEE_Result (*update)(struct crypto_mac_ctx *ctx, const uint8_t *data,
			     size_t len);
	TEE_Result (*final)(struct crypto_mac_ctx *ctx, uint8_t *digest,
			    size_t len);
	void (*free_ctx)(struct crypto_mac_ctx *ctx);
	void (*copy_state)(struct crypto_mac_ctx *dst_ctx,
			   struct crypto_mac_ctx *src_ctx);
};

#if defined(CFG_CRYPTO_HMAC)
TEE_Result crypto_hmac_md5_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_hmac_sha1_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_hmac_sha224_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_hmac_sha256_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_hmac_sha384_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_hmac_sha512_alloc_ctx(struct crypto_mac_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_md5, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha1, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha224, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha256, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha384, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(hmac_sha512, mac)
#endif

#if defined(CFG_CRYPTO_CBC_MAC)
TEE_Result crypto_aes_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_aes_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_des_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_des_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_des3_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx);
TEE_Result crypto_des3_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cbc_mac_nopad, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cbc_mac_pkcs5, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des_cbc_mac_nopad, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des_cbc_mac_pkcs5, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des3_cbc_mac_nopad, mac)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des3_cbc_mac_pkcs5, mac)
#endif

#if defined(CFG_CRYPTO_CMAC)
TEE_Result crypto_aes_cmac_alloc_ctx(struct crypto_mac_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cmac, mac)
#endif

/*
 * The crypto context used by the crypto_cipher_*() functions is defined by
 * struct crypto_cipher_ctx.
 */
struct crypto_cipher_ctx {
	const struct crypto_cipher_ops *ops;
};

struct crypto_cipher_ops {
	TEE_Result (*init)(struct crypto_cipher_ctx *ctx,
			   TEE_OperationMode mode,
			   const uint8_t *key1, size_t key1_len,
			   const uint8_t *key2, size_t key2_len,
			   const uint8_t *iv, size_t iv_len);
	TEE_Result (*update)(struct crypto_cipher_ctx *ctx, bool last_block,
			     const uint8_t *data, size_t len, uint8_t *dst);
	void (*final)(struct crypto_cipher_ctx *ctx);

	void (*free_ctx)(struct crypto_cipher_ctx *ctx);
	void (*copy_state)(struct crypto_cipher_ctx *dst_ctx,
			   struct crypto_cipher_ctx *src_ctx);
};

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_ECB)
TEE_Result crypto_aes_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ecb, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_CBC)
TEE_Result crypto_aes_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cbc, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_CTR)
TEE_Result crypto_aes_ctr_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ctr, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_CTS)
TEE_Result crypto_aes_cts_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_cts, cipher)
#endif

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_XTS)
TEE_Result crypto_aes_xts_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_xts, cipher)
#endif

#if defined(CFG_CRYPTO_DES) && defined(CFG_CRYPTO_ECB)
TEE_Result crypto_des_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx);
TEE_Result crypto_des3_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des_ecb, cipher)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des3_ecb, cipher)
#endif

#if defined(CFG_CRYPTO_DES) && defined(CFG_CRYPTO_CBC)
TEE_Result crypto_des_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx);
TEE_Result crypto_des3_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx);
#else
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des_cbc, cipher)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(des3_cbc, cipher)
#endif

/*
 * The crypto context used by the crypto_authen_*() functions below is
 * defined by struct crypto_authenc_ctx.
 */
struct crypto_authenc_ctx {
	const struct crypto_authenc_ops *ops;
};

struct crypto_authenc_ops {
	TEE_Result (*init)(struct crypto_authenc_ctx *ctx,
			   TEE_OperationMode mode,
			   const uint8_t *key, size_t key_len,
			   const uint8_t *nonce, size_t nonce_len,
			   size_t tag_len, size_t aad_len,
			   size_t payload_len);
	TEE_Result (*update_aad)(struct crypto_authenc_ctx *ctx,
				 const uint8_t *data, size_t len);
	TEE_Result (*update_payload)(struct crypto_authenc_ctx *ctx,
				     TEE_OperationMode mode,
				     const uint8_t *src_data, size_t len,
				     uint8_t *dst_data);
	TEE_Result (*enc_final)(struct crypto_authenc_ctx *ctx,
				const uint8_t *src_data, size_t len,
				uint8_t *dst_data, uint8_t *dst_tag,
				size_t *dst_tag_len);
	TEE_Result (*dec_final)(struct crypto_authenc_ctx *ctx,
				const uint8_t *src_data, size_t len,
				uint8_t *dst_data, const uint8_t *tag,
				size_t tag_len);
	void (*final)(struct crypto_authenc_ctx *ctx);
	void (*free_ctx)(struct crypto_authenc_ctx *ctx);
	void (*copy_state)(struct crypto_authenc_ctx *dst_ctx,
			   struct crypto_authenc_ctx *src_ctx);
};

TEE_Result crypto_aes_ccm_alloc_ctx(struct crypto_authenc_ctx **ctx);
TEE_Result crypto_aes_gcm_alloc_ctx(struct crypto_authenc_ctx **ctx);
#endif /*__CRYPTO_CRYPTO_IMPL_H*/
