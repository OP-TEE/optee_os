// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <se050_cipher_algorithms.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <initcall.h>
#include <string.h>
#include <utee_defines.h>
#include <util.h>

static TEE_Result do_init(struct drvcrypt_cipher_init *dinit)
{
	struct crypto_cipher_ctx *ctx = dinit->ctx;
	TEE_OperationMode mode = TEE_MODE_DECRYPT;

	if (dinit->encrypt)
		mode = TEE_MODE_ENCRYPT;

	return ctx->ops->init(dinit->ctx, mode,
			      dinit->key1.data, dinit->key1.length,
			      dinit->key2.data, dinit->key2.length,
			      dinit->iv.data, dinit->iv.length);
}

static TEE_Result do_update(struct drvcrypt_cipher_update *dupdate)
{
	struct crypto_cipher_ctx *ctx = dupdate->ctx;

	return ctx->ops->update(ctx, dupdate->last, dupdate->src.data,
				dupdate->src.length, dupdate->dst.data);
}

static void do_final(void *context)
{
	struct crypto_cipher_ctx *ctx = context;

	ctx->ops->final(ctx);
}

static void do_free(void *context)
{
	struct crypto_cipher_ctx *ctx = context;

	ctx->ops->free_ctx(ctx);
}

static void do_copy_state(void *out, void *in)
{
	struct crypto_cipher_ctx *dst_ctx = out;
	struct crypto_cipher_ctx *src_ctx = in;

	src_ctx->ops->copy_state(dst_ctx, src_ctx);
}

static TEE_Result do_allocate(void **ctx, uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_CTR:
		return se050_aes_ctr_allocate(ctx);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = do_allocate,
	.free_ctx = do_free,
	.init = do_init,
	.update = do_update,
	.final = do_final,
	.copy_state = do_copy_state,
};

static TEE_Result se050_cipher_init(void)
{
	return drvcrypt_register_cipher(&driver_cipher);
}

driver_init_late(se050_cipher_init);
