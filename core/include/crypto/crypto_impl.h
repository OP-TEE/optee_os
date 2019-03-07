/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __CRYPTO_CRYPTO_IMPL_H
#define __CRYPTO_CRYPTO_IMPL_H

#include <tee_api_types.h>

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
