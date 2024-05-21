// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2024 HiSilicon Limited.
 * Kunpeng hardware accelerator sec hmac algorithm implementation.
 */

#include <drvcrypt_mac.h>
#include <initcall.h>

#include "sec_hash.h"
#include "sec_main.h"

static struct crypto_hmac *to_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	return container_of(ctx, struct crypto_hmac, hmac_op);
}

static TEE_Result sec_hmac_initialize(struct crypto_mac_ctx *ctx,
				      const uint8_t *key, size_t len)
{
	struct crypto_hmac *hash = NULL;
	struct hashctx *hash_ctx = NULL;

	if (!ctx || !key) {
		EMSG("Input ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash = to_hmac_ctx(ctx);
	hash_ctx = hash->ctx;

	return hisi_sec_digest_ctx_init(hash_ctx, key, len);
}

static TEE_Result sec_hmac_do_update(struct crypto_mac_ctx *ctx,
				     const uint8_t *data, size_t len)
{
	struct crypto_hmac *hash = NULL;
	struct hashctx *hashctx = NULL;

	if (!len) {
		IMSG("This is 0 len task, skip");
		return TEE_SUCCESS;
	}

	if (!ctx || (!data && len)) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash = to_hmac_ctx(ctx);
	hashctx = hash->ctx;

	return hisi_sec_digest_do_update(hashctx, data, len);
}

static TEE_Result sec_hmac_do_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				    size_t len)
{
	struct crypto_hmac *hash = to_hmac_ctx(ctx);
	struct hashctx *hash_ctx = hash->ctx;

	return hisi_sec_digest_do_final(hash_ctx, digest, len);
}

static void sec_hmac_ctx_free(struct crypto_mac_ctx *ctx)
{
	struct crypto_hmac *hash = NULL;
	struct hashctx *hash_ctx = NULL;

	if (!ctx)
		return;

	hash = to_hmac_ctx(ctx);
	hash_ctx = hash->ctx;
	if (!hash_ctx)
		return;

	memzero_explicit(hash_ctx->key, hash_ctx->key_len);
	hisi_sec_digest_ctx_free(hash_ctx);

	hash->ctx = NULL;

	free(hash);
}

static void sec_hmac_copy_state(struct crypto_mac_ctx *out_ctx,
				struct crypto_mac_ctx *in_ctx)
{
	struct crypto_hmac *out_hash = NULL;
	struct crypto_hmac *in_hash = NULL;
	struct hashctx *out_hash_ctx = NULL;
	struct hashctx *in_hash_ctx = NULL;

	if (!out_ctx || !in_ctx) {
		EMSG("Invalid input parameters");
		return;
	}

	out_hash = to_hmac_ctx(out_ctx);
	in_hash = to_hmac_ctx(in_ctx);

	out_hash_ctx = out_hash->ctx;
	in_hash_ctx = in_hash->ctx;

	hisi_sec_digest_copy_state(out_hash_ctx, in_hash_ctx);
}

static struct crypto_mac_ops hash_ops = {
	.init = sec_hmac_initialize,
	.update = sec_hmac_do_update,
	.final = sec_hmac_do_final,
	.free_ctx = sec_hmac_ctx_free,
	.copy_state = sec_hmac_copy_state,
};

static TEE_Result sec_hmac_ctx_allocate(struct crypto_mac_ctx **ctx,
					uint32_t algo)
{
	struct crypto_hmac *hash = NULL;
	struct hashctx *hash_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!ctx) {
		EMSG("Ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash = calloc(1, sizeof(*hash));
	if (!hash) {
		EMSG("Fail to alloc hash");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	hash_ctx = calloc(1, sizeof(*hash_ctx));
	if (!hash_ctx) {
		EMSG("Fail to alloc hashctx");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_hash;
	}

	ret = hisi_sec_hash_ctx_init(hash_ctx, algo);
	if (ret)
		goto free_ctx;

	hash->hmac_op.ops = &hash_ops;
	hash->ctx = hash_ctx;
	*ctx = &hash->hmac_op;

	return 0;

free_ctx:
	free(hash_ctx);
free_hash:
	free(hash);

	return ret;
}

static TEE_Result sec_hmac_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_hmac(&sec_hmac_ctx_allocate);
	if (ret)
		EMSG("Sec hmac register to crypto fail");

	return ret;
}
driver_init(sec_hmac_init);
