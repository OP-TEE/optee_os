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

#endif /*__CRYPTO_CRYPTO_IMPL_H*/
