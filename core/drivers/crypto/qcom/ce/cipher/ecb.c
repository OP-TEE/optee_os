// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * AES-ECB cipher context.
 */

#include <ce.h>
#include <crypto/crypto_impl.h>
#include <io.h>
#include <malloc.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>
#include <utee_defines.h>
#include "algorithms.h"

struct ce_ecb_ctx {
	struct crypto_cipher_ctx ctx;
	uint8_t key[32];
	size_t key_len;
	bool encrypt;
};

static struct ce_ecb_ctx *to_ecb(struct crypto_cipher_ctx *ctx)
{
	return container_of(ctx, struct ce_ecb_ctx, ctx);
}

static TEE_Result ecb_init(struct crypto_cipher_ctx *ctx,
			   TEE_OperationMode mode,
			   const uint8_t *key1, size_t key1_len,
			   const uint8_t *key2 __unused,
			   size_t key2_len __unused,
			   const uint8_t *iv __unused,
			   size_t iv_len __unused)
{
	struct ce_ecb_ctx *c = to_ecb(ctx);

	if (key1_len != 16 && key1_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(c->key, key1, key1_len);
	c->key_len = key1_len;
	c->encrypt = (mode == TEE_MODE_ENCRYPT);

	return TEE_SUCCESS;
}

static TEE_Result ecb_update(struct crypto_cipher_ctx *ctx,
			     bool last_block __unused,
			     const uint8_t *data, size_t len, uint8_t *dst)
{
	struct ce_ecb_ctx *c = to_ecb(ctx);
	vaddr_t base = ce_get_base();
	uint32_t encr_cfg = 0;
	uint8_t zero_iv[TEE_AES_BLOCK_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;

	if (len % TEE_AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	encr_cfg = ce_encr_cfg(CE_ENCR_MODE_ECB, c->key_len, c->encrypt);

	ce_lock();

	io_write32_off(base, CE_CONFIG, CE_CONFIG_DEFAULT);
	ce_load_key(base, c->key, c->key_len);
	ce_load_iv(base, zero_iv);
	res = ce_aes_xfer(base, encr_cfg, data, dst, len);

	ce_unlock();

	return res;
}

static void ecb_final(struct crypto_cipher_ctx *ctx)
{
	struct ce_ecb_ctx *c = to_ecb(ctx);

	memzero_explicit(c->key, sizeof(c->key));
}

static void ecb_free(struct crypto_cipher_ctx *ctx)
{
	struct ce_ecb_ctx *c = to_ecb(ctx);

	memzero_explicit(c->key, sizeof(c->key));
	free(c);
}

static void ecb_copy_state(struct crypto_cipher_ctx *dst_ctx,
			   struct crypto_cipher_ctx *src_ctx)
{
	memcpy(to_ecb(dst_ctx), to_ecb(src_ctx),
	       sizeof(struct ce_ecb_ctx));
}

static const struct crypto_cipher_ops ecb_ops = {
	.init = ecb_init,
	.update = ecb_update,
	.final = ecb_final,
	.free_ctx = ecb_free,
	.copy_state = ecb_copy_state,
};

TEE_Result ce_aes_ecb_allocate(void **ctx)
{
	struct ce_ecb_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &ecb_ops;
	*ctx = &c->ctx;

	return TEE_SUCCESS;
}
