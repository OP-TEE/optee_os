// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Qualcomm CRYPTO0 cipher provider - dispatcher.
 */

#include <ce.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <initcall.h>
#include <io.h>
#include <trace.h>
#include <util.h>
#include <utee_defines.h>
#include "algorithms.h"

static TEE_Result do_init(struct drvcrypt_cipher_init *dinit)
{
	struct crypto_cipher_ctx *ctx = dinit->ctx;
	TEE_OperationMode mode = dinit->encrypt ? TEE_MODE_ENCRYPT
						: TEE_MODE_DECRYPT;

	return ctx->ops->init(ctx, mode,
			      dinit->key1.data, dinit->key1.length,
			      dinit->key2.data, dinit->key2.length,
			      dinit->iv.data, dinit->iv.length);
}

static TEE_Result do_update(struct drvcrypt_cipher_update *dupdate)
{
	struct crypto_cipher_ctx *ctx = dupdate->ctx;

	return ctx->ops->update(ctx, dupdate->last,
				dupdate->src.data, dupdate->src.length,
				dupdate->dst.data);
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

static void do_copy_state(void *dst, void *src)
{
	struct crypto_cipher_ctx *dst_ctx = dst;
	struct crypto_cipher_ctx *src_ctx = src;

	src_ctx->ops->copy_state(dst_ctx, src_ctx);
}

static TEE_Result do_allocate(void **ctx, uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		return ce_aes_ecb_allocate(ctx);

	case TEE_ALG_AES_CBC_NOPAD:
		return ce_aes_cbc_allocate(ctx);

	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static struct drvcrypt_cipher ce_cipher_ops = {
	.alloc_ctx = do_allocate,
	.free_ctx = do_free,
	.init = do_init,
	.update = do_update,
	.final = do_final,
	.copy_state = do_copy_state,
};

static TEE_Result ce_cipher_register(void)
{
	vaddr_t base = ce_get_base();

	if (!base)
		return TEE_ERROR_NOT_SUPPORTED;

	if (io_read32_off(base, CE_STATUS2) & CE_STATUS2_BIST_ERROR) {
		EMSG("ce: BIST failure");
		return TEE_ERROR_GENERIC;
	}

	if (!(io_read32_off(base, CE_ENGINES_AVAIL) &
	      CE_ENGINES_AVAIL_ENCR_AES_SEL)) {
		EMSG("ce: AES encryption engine not available");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return drvcrypt_register_cipher(&ce_cipher_ops);
}

driver_init_late(ce_cipher_register);
