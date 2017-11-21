/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <crypto/internal_aes-gcm.h>
#include <kernel/panic.h>
#include <string.h>
#include <tee_api_types.h>
#include <tomcrypt.h>
#include <types_ext.h>

#include "aes-gcm-private.h"

TEE_Result __weak internal_aes_gcm_set_key(struct internal_aes_gcm_ctx *ctx,
					   const void *key, size_t key_len)
{
	if (aes_setup(key, key_len, 0, &ctx->skey))
		return TEE_ERROR_BAD_PARAMETERS;

#ifdef CFG_AES_GCM_TABLE_BASED
	internal_aes_gcm_ghash_gen_tbl(ctx);
#else
	internal_aes_gcm_encrypt_block(ctx, ctx->ctr, ctx->hash_subkey);
#endif

	return TEE_SUCCESS;
}

void __weak internal_aes_gcm_ghash_update(struct internal_aes_gcm_ctx *ctx,
					  const void *head, const void *data,
					  size_t num_blocks)
{
	size_t n;

	if (head)
		internal_aes_gcm_ghash_update_block(ctx, head);

	for (n = 0; n < num_blocks; n++)
		internal_aes_gcm_ghash_update_block(ctx, (uint8_t *)data +
						    n * TEE_AES_BLOCK_SIZE);
}

void __weak
internal_aes_gcm_update_payload_block_aligned(struct internal_aes_gcm_ctx *ctx,
					      TEE_OperationMode m,
					      const void *src,
					      size_t num_blocks, void *dst)
{
	size_t n;
	const uint8_t *s = src;
	uint8_t *d = dst;

	assert(!ctx->buf_pos && num_blocks &&
	       internal_aes_gcm_ptr_is_block_aligned(s) &&
	       internal_aes_gcm_ptr_is_block_aligned(d));

	for (n = 0; n < num_blocks; n++) {
		if (m == TEE_MODE_ENCRYPT) {
			internal_aes_gcm_xor_block(ctx->buf_cryp, s);
			internal_aes_gcm_ghash_update(ctx, ctx->buf_cryp,
						      NULL, 0);
			memcpy(d, ctx->buf_cryp, sizeof(ctx->buf_cryp));
			internal_aes_gcm_encrypt_block(ctx, ctx->ctr,
						       ctx->buf_cryp);
			internal_aes_gcm_inc_ctr(ctx);
		} else {
			internal_aes_gcm_encrypt_block(ctx, ctx->ctr,
						       ctx->buf_cryp);

			internal_aes_gcm_xor_block(ctx->buf_cryp, s);
			internal_aes_gcm_ghash_update(ctx, s, NULL, 0);
			memcpy(d, ctx->buf_cryp, sizeof(ctx->buf_cryp));

			internal_aes_gcm_inc_ctr(ctx);
		}
		s += TEE_AES_BLOCK_SIZE;
		d += TEE_AES_BLOCK_SIZE;
	}
}

void __weak internal_aes_gcm_encrypt_block(struct internal_aes_gcm_ctx *ctx,
					   const void *src, void *dst)
{
	if (aes_ecb_encrypt(src, dst, &ctx->skey))
		panic();
}
