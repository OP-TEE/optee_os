// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt_private.h>
#include <utee_defines.h>

struct shake_ctx {
	struct crypto_hash_ctx ctx;
	struct sha3_state sha3;
};

static struct shake_ctx *to_shake_ctx(struct crypto_hash_ctx *ctx)
{
	return container_of(ctx, struct shake_ctx, ctx);
}

static TEE_Result do_shake_init(struct crypto_hash_ctx *ctx, unsigned int num)
{
	struct shake_ctx *c = to_shake_ctx(ctx);

	if (sha3_shake_init((void *)&c->sha3, num) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result do_sha3_update(struct crypto_hash_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct shake_ctx *c = to_shake_ctx(ctx);

	if (sha3_process((void *)&c->sha3, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result do_shake_final(struct crypto_hash_ctx *ctx,
				 uint8_t *digest, size_t len)
{
	struct shake_ctx *c = to_shake_ctx(ctx);

	if (sha3_shake_done((void *)&c->sha3, digest, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

static TEE_Result do_shake_alloc_ctx(struct crypto_hash_ctx **ctx_ret,
				    const struct crypto_hash_ops *ops)
{
	struct shake_ctx *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ctx->ctx.ops = ops;
	*ctx_ret = &ctx->ctx;

	return TEE_SUCCESS;
}

static void do_sha3_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct shake_ctx *c = to_shake_ctx(ctx);

	free(c);
}
static void do_sha3_copy_state(struct crypto_hash_ctx *dst_ctx,
			       struct crypto_hash_ctx *src_ctx)
{
	struct shake_ctx *dc = to_shake_ctx(dst_ctx);
	struct shake_ctx *sc = to_shake_ctx(src_ctx);

	assert(sc->ctx.ops == dc->ctx.ops);
	dc->sha3 = sc->sha3;
}

#if defined(_CFG_CORE_LTC_SHAKE128)
static TEE_Result do_shake128_init(struct crypto_hash_ctx *ctx)
{
	return do_shake_init(ctx, 128);
}

static const struct crypto_hash_ops shake128_ops = {
	.init = do_shake128_init,
	.update = do_sha3_update,
	.final = do_shake_final,
	.free_ctx = do_sha3_free_ctx,
	.copy_state = do_sha3_copy_state,
};

TEE_Result crypto_shake128_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return do_shake_alloc_ctx(ctx, &shake128_ops);
}
#endif

#if defined(_CFG_CORE_LTC_SHAKE256)
static TEE_Result do_shake256_init(struct crypto_hash_ctx *ctx)
{
	return do_shake_init(ctx, 256);
}

static const struct crypto_hash_ops shake256_ops = {
	.init = do_shake256_init,
	.update = do_sha3_update,
	.final = do_shake_final,
	.free_ctx = do_sha3_free_ctx,
	.copy_state = do_sha3_copy_state,
};

TEE_Result crypto_shake256_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return do_shake_alloc_ctx(ctx, &shake256_ops);
}
#endif
