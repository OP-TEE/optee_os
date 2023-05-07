// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022 Huawei Technologies Co., Ltd
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <util.h>
#include "sm4.h"

struct sm4_xts_ctx {
	struct crypto_cipher_ctx ctx;
	struct sm4_context state;
	struct sm4_context state_ek;
	struct sm4_context state_dk;
	uint8_t iv[16];
};

static const struct crypto_cipher_ops sm4_xts_ops;

static struct sm4_xts_ctx *to_sm4_xts_ctx(struct crypto_cipher_ctx *ctx)
{
	assert(ctx && ctx->ops == &sm4_xts_ops);

	return container_of(ctx, struct sm4_xts_ctx, ctx);
}

static TEE_Result sm4_xts_init(struct crypto_cipher_ctx *ctx,
			       TEE_OperationMode mode, const uint8_t *key1,
			       size_t key1_len, const uint8_t *key2,
			       size_t key2_len, const uint8_t *iv,
			       size_t iv_len)
{
	struct sm4_xts_ctx *c = to_sm4_xts_ctx(ctx);

	if (key1_len != 16 || key2_len != 16 || iv_len != sizeof(c->iv))
		return TEE_ERROR_BAD_STATE;

	if (iv)
		memcpy(c->iv, iv, sizeof(c->iv));

	if (mode == TEE_MODE_ENCRYPT)
		sm4_setkey_enc(&c->state, key1);
	else
		sm4_setkey_dec(&c->state, key1);

	sm4_setkey_enc(&c->state_ek, key2);
	sm4_setkey_dec(&c->state_dk, key2);

	return TEE_SUCCESS;
}

static TEE_Result sm4_xts_update(struct crypto_cipher_ctx *ctx,
				 bool last_block __unused, const uint8_t *data,
				 size_t len, uint8_t *dst)
{
	struct sm4_xts_ctx *c = to_sm4_xts_ctx(ctx);

	sm4_crypt_xts(&c->state, &c->state_ek, &c->state_dk,
		      len, c->iv, data, dst);

	return TEE_SUCCESS;
}

static void sm4_xts_final(struct crypto_cipher_ctx *ctx)
{
	struct sm4_xts_ctx *c = to_sm4_xts_ctx(ctx);

	memzero_explicit(&c->state, sizeof(c->state));
	memzero_explicit(&c->state_ek, sizeof(c->state_ek));
	memzero_explicit(&c->state_dk, sizeof(c->state_dk));
	memzero_explicit(&c->iv, sizeof(c->iv));
}

static void sm4_xts_free_ctx(struct crypto_cipher_ctx *ctx)
{
	free(to_sm4_xts_ctx(ctx));
}

static void sm4_xts_copy_state(struct crypto_cipher_ctx *dst_ctx,
			       struct crypto_cipher_ctx *src_ctx)
{
	struct sm4_xts_ctx *src = to_sm4_xts_ctx(src_ctx);
	struct sm4_xts_ctx *dst = to_sm4_xts_ctx(dst_ctx);

	dst->state = src->state;
	dst->state_ek = src->state_ek;
	dst->state_dk = src->state_dk;
	memcpy(dst->iv, src->iv, sizeof(src->iv));
}

static const struct crypto_cipher_ops sm4_xts_ops = {
	.init = sm4_xts_init,
	.update = sm4_xts_update,
	.final = sm4_xts_final,
	.free_ctx = sm4_xts_free_ctx,
	.copy_state = sm4_xts_copy_state,
};

TEE_Result crypto_sm4_xts_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	struct sm4_xts_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &sm4_xts_ops;
	*ctx_ret = &c->ctx;

	return TEE_SUCCESS;
}
