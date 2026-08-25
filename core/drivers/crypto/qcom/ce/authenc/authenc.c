// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Qualcomm CRYPTO0 AEAD provider - dispatcher.
 */

#include <ce.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <io.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <utee_defines.h>
#include "algorithms.h"

static TEE_Result do_alloc_ctx(void **ctx, uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_GCM:
		return ce_aes_gcm_allocate(ctx);

	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static void do_free_ctx(void *ctx)
{
	struct crypto_authenc_ctx *ae_ctx = ctx;

	ae_ctx->ops->free_ctx(ae_ctx);
}

static TEE_Result do_init(struct drvcrypt_authenc_init *dinit)
{
	struct crypto_authenc_ctx *ctx = dinit->ctx;
	TEE_OperationMode mode = dinit->encrypt ? TEE_MODE_ENCRYPT
						: TEE_MODE_DECRYPT;

	return ctx->ops->init(ctx, mode,
			      dinit->key.data, dinit->key.length,
			      dinit->nonce.data, dinit->nonce.length,
			      dinit->tag_len,
			      dinit->aad_len,
			      dinit->payload_len);
}

static TEE_Result do_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct crypto_authenc_ctx *ctx = dupdate->ctx;

	return ctx->ops->update_aad(ctx, dupdate->aad.data,
				    dupdate->aad.length);
}

static TEE_Result
do_update_payload(struct drvcrypt_authenc_update_payload *dupdate)
{
	struct crypto_authenc_ctx *ctx = dupdate->ctx;
	TEE_OperationMode mode = dupdate->encrypt ? TEE_MODE_ENCRYPT
						  : TEE_MODE_DECRYPT;

	return ctx->ops->update_payload(ctx, mode,
					dupdate->src.data,
					dupdate->src.length,
					dupdate->dst.data);
}

static TEE_Result do_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	struct crypto_authenc_ctx *ctx = dfinal->ctx;

	return ctx->ops->enc_final(ctx, dfinal->src.data, dfinal->src.length,
				   dfinal->dst.data, dfinal->tag.data,
				   &dfinal->tag.length);
}

static TEE_Result do_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	struct crypto_authenc_ctx *ctx = dfinal->ctx;

	return ctx->ops->dec_final(ctx, dfinal->src.data, dfinal->src.length,
				   dfinal->dst.data, dfinal->tag.data,
				   dfinal->tag.length);
}

static void do_final(void *ctx)
{
	struct crypto_authenc_ctx *ae_ctx = ctx;

	ae_ctx->ops->final(ae_ctx);
}

static void do_copy_state(void *dst, void *src)
{
	struct crypto_authenc_ctx *dst_ctx = dst;
	struct crypto_authenc_ctx *src_ctx = src;

	src_ctx->ops->copy_state(dst_ctx, src_ctx);
}

static struct drvcrypt_authenc ce_authenc_ops = {
	.alloc_ctx = do_alloc_ctx,
	.free_ctx = do_free_ctx,
	.init = do_init,
	.update_aad = do_update_aad,
	.update_payload = do_update_payload,
	.enc_final = do_enc_final,
	.dec_final = do_dec_final,
	.final = do_final,
	.copy_state = do_copy_state,
};

static TEE_Result ce_authenc_register(void)
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
		EMSG("ce: AES engine not available");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return drvcrypt_register_authenc(&ce_authenc_ops);
}

driver_init_late(ce_authenc_register);
