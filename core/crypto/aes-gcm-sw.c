/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * gfmul() is based on ghash_gfmul from
 * https://github.com/openbsd/src/blob/master/sys/crypto/gmac.c
 * Which is:
 * Copyright (c) 2010 Mike Belopuhov
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <crypto/internal_aes-gcm.h>
#include <kernel/panic.h>
#include <string.h>
#include <tee_api_types.h>
#include <tomcrypt.h>
#include <types_ext.h>

static bool __maybe_unused ptr_is_block_aligned(const void *p)
{
	return !((vaddr_t)p & (TEE_AES_BLOCK_SIZE - 1));
}

static void xor_block(void *dst, const void *src)
{
	uint64_t *d = dst;
	const uint64_t *s = src;

	d[0] ^= s[0];
	d[1] ^= s[1];
}

TEE_Result __weak internal_aes_gcm_set_key(struct internal_aes_gcm_ctx *ctx,
					   const void *key, size_t key_len)
{
	if (aes_setup(key, key_len, 0, &ctx->skey))
		return TEE_ERROR_BAD_PARAMETERS;

	if (aes_ecb_encrypt((void *)ctx->ctr, ctx->hash_subkey, &ctx->skey))
		panic();

	return TEE_SUCCESS;
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
	       ptr_is_block_aligned(s) && ptr_is_block_aligned(d));

	for (n = 0; n < num_blocks; n++) {
		if (m == TEE_MODE_ENCRYPT) {
			xor_block(ctx->buf_cryp, s);
			internal_aes_gcm_ghash_update(ctx, ctx->buf_cryp,
						      NULL, 0);
			memcpy(d, ctx->buf_cryp, sizeof(ctx->buf_cryp));
			internal_aes_gcm_encrypt_block(ctx, ctx->ctr,
						       ctx->buf_cryp);
			internal_aes_gcm_inc_ctr(ctx);
		} else {
			internal_aes_gcm_encrypt_block(ctx, ctx->ctr,
						       ctx->buf_cryp);

			xor_block(ctx->buf_cryp, s);
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
