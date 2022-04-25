// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Aspeed Technology Inc.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <io.h>
#include <util.h>
#include <drvcrypt_hash.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <kernel/delay.h>
#include <tee/cache.h>

#include "hace_ast2600.h"

#define HACE_BASE	0x1e6d0000

/* register offsets and bit fields */
#define HACE_STS		0x1C
#define   HACE_STS_HASH_INT		BIT(9)
#define   HACE_STS_HASH_BUSY		BIT(0)
#define HACE_HASH_DATA		0x20
#define HACE_HASH_DIGEST	0x24
#define HACE_HASH_HMAC_KEY	0x28
#define HACE_HASH_DATA_LEN	0x2C
#define HACE_HASH_CMD		0x30
#define   HACE_HASH_CMD_ACCUM		BIT(8)
#define   HACE_HASH_CMD_ALG_SHA1	BIT(5)
#define   HACE_HASH_CMD_ALG_SHA256	(BIT(6) | BIT(4))
#define   HACE_HASH_CMD_ALG_SHA384	(BIT(10) | BIT(6) | BIT(5))
#define   HACE_HASH_CMD_ALG_SHA512	(BIT(6) | BIT(5))
#define   HACE_HASH_CMD_SHA_BE		BIT(3)

/* buffer size based on SHA-512 need */
#define HASH_BLK_BUFSZ	128
#define HASH_DGT_BUFSZ	64

register_phys_mem(MEM_AREA_IO_SEC, HACE_BASE, SMALL_PAGE_SIZE);

struct ast2600_hace_ctx {
	struct crypto_hash_ctx hash_ctx;
	uint32_t cmd;
	uint32_t algo;
	uint32_t dgt_size;
	uint32_t blk_size;
	uint32_t pad_size;
	uint64_t total[2];

	/* DMA memory to interact with HACE */
	uint8_t *buf;
	uint8_t *digest;
};

static vaddr_t hace_virt;
struct mutex hace_mtx = MUTEX_INITIALIZER;

static const uint32_t iv_sha1[8] = {
	0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
	0xf0e1d2c3, 0, 0, 0
};

static const uint32_t iv_sha256[8] = {
	0x67e6096a, 0x85ae67bb, 0x72f36e3c, 0x3af54fa5,
	0x7f520e51, 0x8c68059b, 0xabd9831f, 0x19cde05b
};

static const uint32_t iv_sha384[16] = {
	0x5d9dbbcb, 0xd89e05c1, 0x2a299a62, 0x07d57c36,
	0x5a015991, 0x17dd7030, 0xd8ec2f15, 0x39590ef7,
	0x67263367, 0x310bc0ff, 0x874ab48e, 0x11155868,
	0x0d2e0cdb, 0xa78ff964, 0x1d48b547, 0xa44ffabe
};

static const uint32_t iv_sha512[16] = {
	0x67e6096a, 0x08c9bcf3, 0x85ae67bb, 0x3ba7ca84,
	0x72f36e3c, 0x2bf894fe, 0x3af54fa5, 0xf1361d5f,
	0x7f520e51, 0xd182e6ad, 0x8c68059b, 0x1f6c3e2b,
	0xabd9831f, 0x6bbd41fb, 0x19cde05b, 0x79217e13
};

static TEE_Result ast2600_hace_process(struct crypto_hash_ctx *ctx,
				       const uint8_t *data, size_t len)
{
	TEE_Result rc = TEE_ERROR_GENERIC;
	uint32_t sts = 0;
	uint64_t tref = 0;
	paddr_t data_phys = 0;
	paddr_t digest_phys = 0;
	struct ast2600_hace_ctx *hctx = NULL;

	mutex_lock(&hace_mtx);

	hctx = container_of(ctx, struct ast2600_hace_ctx, hash_ctx);

	sts = io_read32(hace_virt + HACE_STS);
	if (sts & HACE_STS_HASH_BUSY) {
		rc = TEE_ERROR_BUSY;
		goto out;
	}

	cache_operation(TEE_CACHEFLUSH, (void *)data, len);

	data_phys = virt_to_phys((void *)data);
	digest_phys = virt_to_phys(hctx->digest);

	io_write32(hace_virt + HACE_HASH_DATA, (uint32_t)data_phys);
	io_write32(hace_virt + HACE_HASH_DIGEST, (uint32_t)digest_phys);
	io_write32(hace_virt + HACE_HASH_HMAC_KEY, (uint32_t)digest_phys);

	io_write32(hace_virt + HACE_HASH_DATA_LEN, len);
	io_write32(hace_virt + HACE_HASH_CMD, hctx->cmd);

	/* poll for completion */
	tref = timeout_init_us(1000 + (len >> 3));

	do {
		sts = io_read32(hace_virt + HACE_STS);
		if (timeout_elapsed(tref)) {
			rc = TEE_ERROR_TARGET_DEAD;
			goto out;
		}
	} while (!(sts & HACE_STS_HASH_INT));

	io_write32(hace_virt + HACE_STS, HACE_STS_HASH_INT);

	rc = TEE_SUCCESS;
out:
	mutex_unlock(&hace_mtx);

	return rc;
}

static TEE_Result ast2600_hace_init(struct crypto_hash_ctx *ctx)
{
	struct ast2600_hace_ctx *hctx = NULL;

	hctx = container_of(ctx, struct ast2600_hace_ctx, hash_ctx);

	switch (hctx->algo) {
	case TEE_ALG_SHA1:
		memcpy(hctx->digest, iv_sha1, sizeof(iv_sha1));
		break;
	case TEE_ALG_SHA256:
		memcpy(hctx->digest, iv_sha256, sizeof(iv_sha256));
		break;
	case TEE_ALG_SHA384:
		memcpy(hctx->digest, iv_sha384, sizeof(iv_sha384));
		break;
	case TEE_ALG_SHA512:
		memcpy(hctx->digest, iv_sha512, sizeof(iv_sha512));
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	hctx->total[0] = 0;
	hctx->total[1] = 0;

	cache_operation(TEE_CACHEFLUSH, hctx->digest, HASH_DGT_BUFSZ);

	return TEE_SUCCESS;
}

static TEE_Result ast2600_hace_update(struct crypto_hash_ctx *ctx,
				      const uint8_t *data, size_t len)
{
	TEE_Result rc = TEE_ERROR_GENERIC;
	uint32_t left = 0;
	uint32_t fill = 0;
	size_t blk_size = 0;
	struct ast2600_hace_ctx *hctx = NULL;

	if (!ctx || !data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	hctx = container_of(ctx, struct ast2600_hace_ctx, hash_ctx);

	blk_size = hctx->blk_size;

	left = hctx->total[0] & (blk_size - 1);
	fill = blk_size - left;

	hctx->total[0] += len;
	if (hctx->total[0] < len)
		hctx->total[1]++;

	if (left && len >= fill) {
		memcpy(hctx->buf + left, data, fill);
		rc = ast2600_hace_process(ctx, hctx->buf, blk_size);
		if (rc)
			return rc;

		data += fill;
		len -= fill;
		left = 0;
	}

	while (len >= blk_size) {
		memcpy(hctx->buf, data, blk_size);
		rc = ast2600_hace_process(ctx, hctx->buf, blk_size);
		if (rc)
			return rc;

		data += blk_size;
		len -= blk_size;
	}

	if (len)
		memcpy(hctx->buf + left, data, len);

	return TEE_SUCCESS;
}

static TEE_Result ast2600_hace_final(struct crypto_hash_ctx *ctx,
				     uint8_t *digest, size_t len)
{
	TEE_Result rc = TEE_ERROR_GENERIC;
	uint32_t last = 0;
	uint32_t padn = 0;
	uint8_t pad[HASH_BLK_BUFSZ * 2] = { };
	uint64_t dbits[2] = { };
	uint64_t dbits_be[2] = { };
	struct ast2600_hace_ctx *hctx = NULL;
	size_t length = 0;

	hctx = container_of(ctx, struct ast2600_hace_ctx, hash_ctx);
	length = MIN(len, hctx->dgt_size);

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;

	dbits[0] = (hctx->total[0] << 3);
	dbits_be[0] = get_be64(&dbits[0]);

	dbits[1] = (hctx->total[0] >> 61) | (hctx->total[1] << 3);
	dbits_be[1] = get_be64(&dbits[1]);

	last = hctx->total[0] & (hctx->blk_size - 1);

	switch (hctx->algo) {
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
		if (last < 56)
			padn = 56 - last;
		else
			padn = 120 - last;

		rc = ast2600_hace_update(ctx, pad, padn);
		if (rc)
			return rc;

		rc = ast2600_hace_update(ctx, (uint8_t *)&dbits_be[0],
					 sizeof(dbits_be[0]));
		if (rc)
			return rc;
		break;
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
		if (last < 112)
			padn = 112 - last;
		else
			padn = 240 - last;

		rc = ast2600_hace_update(ctx, pad, padn);
		if (rc)
			return rc;

		rc = ast2600_hace_update(ctx, (uint8_t *)&dbits_be[1],
					 sizeof(dbits_be[1]));
		if (rc)
			return rc;

		rc = ast2600_hace_update(ctx, (uint8_t *)&dbits_be[0],
					 sizeof(dbits_be[0]));
		if (rc)
			return rc;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	cache_operation(TEE_CACHEINVALIDATE, hctx->digest, HASH_DGT_BUFSZ);

	memcpy(digest, hctx->digest, length);

	return TEE_SUCCESS;
}

static void ast2600_hace_free(struct crypto_hash_ctx *ctx)
{
	struct ast2600_hace_ctx *hctx = NULL;

	hctx = container_of(ctx, struct ast2600_hace_ctx, hash_ctx);

	free(hctx->buf);
	free(hctx->digest);
	free(hctx);
}

static void ast2600_hace_copy_state(struct crypto_hash_ctx *dst_ctx,
				    struct crypto_hash_ctx *src_ctx)
{
	struct ast2600_hace_ctx *src_hctx = NULL;
	struct ast2600_hace_ctx *dst_hctx = NULL;

	src_hctx = container_of(src_ctx, struct ast2600_hace_ctx, hash_ctx);
	dst_hctx = container_of(dst_ctx, struct ast2600_hace_ctx, hash_ctx);

	dst_hctx->hash_ctx = src_hctx->hash_ctx;
	dst_hctx->cmd = src_hctx->cmd;
	dst_hctx->dgt_size = src_hctx->dgt_size;
	dst_hctx->blk_size = src_hctx->blk_size;
	dst_hctx->pad_size = src_hctx->pad_size;
	dst_hctx->total[0] = src_hctx->total[0];
	dst_hctx->total[1] = src_hctx->total[1];

	cache_operation(TEE_CACHEINVALIDATE, src_hctx->buf, HASH_BLK_BUFSZ);
	memcpy(dst_hctx->buf, src_hctx->buf, HASH_BLK_BUFSZ);
	cache_operation(TEE_CACHEFLUSH,	dst_hctx->buf, HASH_BLK_BUFSZ);

	cache_operation(TEE_CACHEINVALIDATE, src_hctx->digest, HASH_DGT_BUFSZ);
	memcpy(dst_hctx->digest, src_hctx->digest, HASH_DGT_BUFSZ);
	cache_operation(TEE_CACHEFLUSH,	dst_hctx->digest, HASH_DGT_BUFSZ);
}

static const struct crypto_hash_ops ast2600_hace_ops = {
	.init = ast2600_hace_init,
	.update = ast2600_hace_update,
	.final = ast2600_hace_final,
	.free_ctx = ast2600_hace_free,
	.copy_state = ast2600_hace_copy_state,
};

static TEE_Result ast2600_hace_alloc(struct crypto_hash_ctx **pctx,
				     uint32_t algo)
{
	struct ast2600_hace_ctx *hctx = calloc(1, sizeof(*hctx));

	if (!hctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	hctx->buf = memalign(HASH_BLK_BUFSZ, HASH_BLK_BUFSZ);
	if (!hctx->buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	hctx->digest = memalign(HASH_DGT_BUFSZ, HASH_DGT_BUFSZ);
	if (!hctx->digest)
		return TEE_ERROR_OUT_OF_MEMORY;

	hctx->hash_ctx.ops = &ast2600_hace_ops;
	hctx->algo = algo;
	hctx->cmd = HACE_HASH_CMD_ACCUM | HACE_HASH_CMD_SHA_BE;

	switch (algo) {
	case TEE_ALG_SHA1:
		hctx->dgt_size = 20;
		hctx->blk_size = 64;
		hctx->pad_size = 8;
		hctx->cmd |= HACE_HASH_CMD_ALG_SHA1;
		break;
	case TEE_ALG_SHA256:
		hctx->dgt_size = 32;
		hctx->blk_size = 64;
		hctx->pad_size = 8;
		hctx->cmd |= HACE_HASH_CMD_ALG_SHA256;
		break;
	case TEE_ALG_SHA384:
		hctx->dgt_size = 48;
		hctx->blk_size = 128;
		hctx->pad_size = 16;
		hctx->cmd |= HACE_HASH_CMD_ALG_SHA384;
		break;
	case TEE_ALG_SHA512:
		hctx->dgt_size = 64;
		hctx->blk_size = 128;
		hctx->pad_size = 16;
		hctx->cmd |= HACE_HASH_CMD_ALG_SHA512;
		break;
	default:
		free(hctx);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	*pctx = &hctx->hash_ctx;

	return TEE_SUCCESS;
}

TEE_Result ast2600_drvcrypt_register_hash(void)
{
	hace_virt = core_mmu_get_va(HACE_BASE, MEM_AREA_IO_SEC,
				    SMALL_PAGE_SIZE);
	if (!hace_virt) {
		EMSG("cannot get HACE virtual address");
		return TEE_ERROR_GENERIC;
	}

	return drvcrypt_register_hash(ast2600_hace_alloc);
}
