// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

/*
 * This is implemented here as being the plain text which is encoded with IV=0.
 * Result of the CBC-MAC is the last 16-bytes cipher.
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

#define CBCMAC_MAX_BLOCK_LEN 16

struct crypto_cbc_mac_ctx {
	struct crypto_mac_ctx ctx;
	void *cbc_ctx;
	uint32_t cbc_algo;
	uint8_t block[CBCMAC_MAX_BLOCK_LEN];
	uint8_t digest[CBCMAC_MAX_BLOCK_LEN];
	unsigned char current_block_len;
	unsigned char block_len;
	bool is_computed;
	bool pkcs5_pad;
};

static const struct crypto_mac_ops crypto_cbc_mac_ops;

static struct crypto_cbc_mac_ctx *to_cbc_mac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &crypto_cbc_mac_ops);

	return container_of(ctx, struct crypto_cbc_mac_ctx, ctx);
}

static TEE_Result crypto_cbc_mac_init(struct crypto_mac_ctx *ctx,
				      const uint8_t *key, size_t len)
{
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	memset(mc->block, 0, sizeof(mc->block));
	memset(mc->digest, 0, sizeof(mc->digest));
	mc->current_block_len = 0;
	mc->is_computed = false;

	/* IV should be zero and mc->block happens to be zero at this stage */
	return crypto_cipher_init(mc->cbc_ctx, TEE_MODE_ENCRYPT, key, len,
				  NULL, 0, mc->block, mc->block_len);
}

static TEE_Result crypto_cbc_mac_update(struct crypto_mac_ctx *ctx,
					const uint8_t *data, size_t len)
{
	size_t nblocks = 0;
	size_t out_len = 0;
	uint8_t *out_tmp = NULL;
	uint8_t *out = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	if ((mc->current_block_len > 0) &&
	    (len + mc->current_block_len >= mc->block_len)) {
		size_t pad_len = mc->block_len - mc->current_block_len;

		memcpy(mc->block + mc->current_block_len, data, pad_len);
		data += pad_len;
		len -= pad_len;
		res = crypto_cipher_update(mc->cbc_ctx, TEE_MODE_ENCRYPT,
					   false, mc->block, mc->block_len,
					   mc->digest);
		if (res)
			return res;
		mc->is_computed = 1;
		mc->current_block_len = 0;
	}

	nblocks = MIN(len / mc->block_len,
		      (size_t)CFG_CRYPTO_CBC_MAC_BUNDLE_BLOCKS);
	if (nblocks > 1)
		out_tmp = malloc(nblocks * mc->block_len);

	while (len >= mc->block_len) {
		nblocks = MIN(len / mc->block_len,
			      (size_t)CFG_CRYPTO_CBC_MAC_BUNDLE_BLOCKS);

		if (nblocks > 1 && out_tmp) {
			out_len = nblocks * mc->block_len;
			out = out_tmp;
		} else {
			out_len = mc->block_len;
			out = mc->digest;
			nblocks = 1;
		}

		res = crypto_cipher_update(mc->cbc_ctx, TEE_MODE_ENCRYPT,
					   false, data, out_len, out);
		if (res)
			goto out;
		mc->is_computed = 1;
		data += out_len;
		len -= out_len;
		if (nblocks > 1 && len < mc->block_len) {
			assert(out_tmp);
			/* Copy last block of output */
			memcpy(mc->digest, out_tmp + out_len - mc->block_len,
			       mc->block_len);
		}
	}

	if (len > 0) {
		assert(mc->current_block_len + len < mc->block_len);
		memcpy(mc->block + mc->current_block_len, data, len);
		mc->current_block_len += len;
	}

out:
	free(out_tmp);
	return res;
}

static TEE_Result crypto_cbc_mac_final(struct crypto_mac_ctx *ctx,
				       uint8_t *digest, size_t digest_len)
{
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	if (mc->pkcs5_pad) {
		/*
		 * Padding is in whole bytes. The value of each added
		 * byte is the number of bytes that are added, i.e. N
		 * bytes, each of value N are added
		 */
		size_t pad_len = mc->block_len - mc->current_block_len;

		memset(mc->block + mc->current_block_len, pad_len, pad_len);
		mc->current_block_len = 0;
		if (crypto_cbc_mac_update(ctx, mc->block, mc->block_len))
			return TEE_ERROR_BAD_STATE;
	}

	if (!mc->is_computed || mc->current_block_len)
		return TEE_ERROR_BAD_STATE;

	memcpy(digest, mc->digest, MIN(digest_len, mc->block_len));
	crypto_cipher_final(mc->cbc_ctx);

	return TEE_SUCCESS;
}

static void crypto_cbc_mac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct crypto_cbc_mac_ctx *mc = to_cbc_mac_ctx(ctx);

	crypto_cipher_free_ctx(mc->cbc_ctx);
	free(mc);
}

static void crypto_cbc_mac_copy_state(struct crypto_mac_ctx *dst_ctx,
				      struct crypto_mac_ctx *src_ctx)
{
	struct crypto_cbc_mac_ctx *dst = to_cbc_mac_ctx(dst_ctx);
	struct crypto_cbc_mac_ctx *src = to_cbc_mac_ctx(src_ctx);

	assert(dst->block_len == src->block_len);
	assert(dst->pkcs5_pad == src->pkcs5_pad);
	assert(dst->cbc_algo == src->cbc_algo);

	crypto_cipher_copy_state(dst->cbc_ctx, src->cbc_ctx);
	memcpy(dst->block, src->block, sizeof(dst->block));
	memcpy(dst->digest, src->digest, sizeof(dst->digest));
	dst->current_block_len = src->current_block_len;
	dst->is_computed = src->is_computed;
}

static const struct crypto_mac_ops crypto_cbc_mac_ops = {
	.init = crypto_cbc_mac_init,
	.update = crypto_cbc_mac_update,
	.final = crypto_cbc_mac_final,
	.free_ctx = crypto_cbc_mac_free_ctx,
	.copy_state = crypto_cbc_mac_copy_state,
};

static TEE_Result crypto_cbc_mac_alloc_ctx(struct crypto_mac_ctx **ctx_ret,
					   uint32_t cbc_algo, bool pkcs5_pad)
{
	TEE_Result res;
	void *cbc_ctx = NULL;
	struct crypto_cbc_mac_ctx *ctx = NULL;
	size_t block_size = 0;

	res = crypto_cipher_get_block_size(cbc_algo, &block_size);
	if (res)
		return res;

	res = crypto_cipher_alloc_ctx(&cbc_ctx, cbc_algo);
	if (res)
		return res;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		crypto_cipher_free_ctx(cbc_ctx);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ctx->cbc_ctx = cbc_ctx;
	ctx->cbc_algo = cbc_algo;
	ctx->pkcs5_pad = pkcs5_pad;
	ctx->block_len = block_size;
	ctx->ctx.ops = &crypto_cbc_mac_ops;
	*ctx_ret = &ctx->ctx;

	return TEE_SUCCESS;
}

TEE_Result crypto_aes_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_AES_CBC_NOPAD, false);
}

TEE_Result crypto_aes_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_AES_CBC_NOPAD, true);
}

TEE_Result crypto_des_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES_CBC_NOPAD, false);
}

TEE_Result crypto_des_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES_CBC_NOPAD, true);
}

TEE_Result crypto_des3_cbc_mac_nopad_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES3_CBC_NOPAD, false);
}

TEE_Result crypto_des3_cbc_mac_pkcs5_alloc_ctx(struct crypto_mac_ctx **ctx)
{
	return crypto_cbc_mac_alloc_ctx(ctx, TEE_ALG_DES3_CBC_NOPAD, true);
}
