// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drivers/amd/asu_client.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <initcall.h>
#include <kernel/cache_helpers.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <string.h>
#include <string_ext.h>
#include <tee/cache.h>
#include <trace.h>
#include <util.h>

/* Cipher Command IDs */
#define ASU_CIPHER_OPERATION_CMD_ID	0x0U

/* Cipher operation flags */
#define ASU_CIPHER_INIT			0x1U
#define ASU_CIPHER_UPDATE		0x2U
#define ASU_CIPHER_FINAL		0x4U

/* Cipher Block size in bytes */
#define ASU_CIPHER_BLOCK_SIZE		16U

/* Cipher Key sizes in bytes */
#define AES_KEYSIZE_128			16U
#define AES_KEYSIZE_192			24U
#define AES_KEYSIZE_256			32U

/* Cipher Key size encoding */
#define ASU_CIPHER_KEY_SIZE_128_BITS	0x0U
#define ASU_CIPHER_KEY_SIZE_256_BITS	0x2U

#define ASU_CIPHER_CTR_INCREMENT	1U
#define ASU_CIPHER_CTR32_WRAP_INCREMENT	1UL
/* Cipher engine modes */
#define ASU_CIPHER_CBC_MODE		0x0U
#define ASU_CIPHER_CTR_MODE		0x3U
#define ASU_CIPHER_ECB_MODE		0x4U

/* Cipher operation types */
#define ASU_CIPHER_ENCRYPT_OPERATION	0x0U
#define ASU_CIPHER_DECRYPT_OPERATION	0x1U

/* Cipher key sources */
#define ASU_CIPHER_USER_KEY_0		0x0U

/* Data chunk length */
#define ASU_CIPHER_DATA_CHUNK_LEN	4096U

/* IV size in 64-bit words */
#define ASU_CIPHER_IV_SIZE		2U

struct asu_cipher_key_object {
	uint64_t keyaddr;
	uint32_t keysize;
	uint32_t keysrc;
	uint32_t keyid;
};

struct asu_cipher_op_cmd {
	uint64_t inputdataaddr;
	uint64_t outputdataaddr;
	uint64_t aadaddr;
	uint64_t keyobjectaddr;
	uint64_t ivaddr;
	uint64_t tagaddr;
	uint32_t datalen;
	uint32_t aadlen;
	uint32_t ivlen;
	uint32_t taglen;
	uint8_t enginemode;
	uint8_t operationflags;
	uint8_t islast;
	uint8_t operationtype;
	uint32_t ivid;
};

struct asu_cipher_ctx {
	struct asu_client_params cparam;
	struct asu_cipher_key_object key_obj;
	uint32_t ciphermode;
	uint32_t optype;
	uint32_t keysize;
	uint32_t hw_keysize;
	uint8_t uniqueid;
	uint8_t stream_offset;
	uint8_t key[AES_KEYSIZE_256];
	uint64_t iv[ASU_CIPHER_IV_SIZE];
	uint8_t keystream[ASU_CIPHER_BLOCK_SIZE];
	/* Software fallback for 192-bit keys */
	bool use_sw_fallback;
	struct crypto_cipher_ctx *sw_ctx;
};

/*
 * asu_cipher_get_cipher_mode() - Map TEE algorithm to ASU cipher mode.
 * @algo:	TEE algorithm type
 * @mode:	ASU cipher mode
 *
 * Return: TEE_SUCCESS or TEE_ERROR_NOT_SUPPORTED.
 */
static TEE_Result asu_cipher_get_cipher_mode(uint32_t algo, uint32_t *mode)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		*mode = ASU_CIPHER_ECB_MODE;
		return TEE_SUCCESS;
	case TEE_ALG_AES_CBC_NOPAD:
		*mode = ASU_CIPHER_CBC_MODE;
		return TEE_SUCCESS;
	case TEE_ALG_AES_CTR:
		*mode = ASU_CIPHER_CTR_MODE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Software fallback functions for 192-bit key support
 */
static void __maybe_unused asu_cipher_sw_free_ctx(struct asu_cipher_ctx *ctx)
{
	if (ctx->sw_ctx) {
		ctx->sw_ctx->ops->free_ctx(ctx->sw_ctx);
		ctx->sw_ctx = NULL;
	}
}

static void __maybe_unused asu_cipher_sw_copy_state(struct asu_cipher_ctx *dst,
						    struct asu_cipher_ctx *src)
{
	src->sw_ctx->ops->copy_state(dst->sw_ctx, src->sw_ctx);
}

static void __maybe_unused asu_cipher_sw_final(struct asu_cipher_ctx *ctx)
{
	ctx->sw_ctx->ops->final(ctx->sw_ctx);
}

static TEE_Result __maybe_unused
asu_cipher_sw_update(struct asu_cipher_ctx *ctx, bool last,
		     uint8_t *src, size_t len, uint8_t *dst)
{
	return ctx->sw_ctx->ops->update(ctx->sw_ctx, last, src, len, dst);
}

static TEE_Result __maybe_unused
asu_cipher_sw_init(struct asu_cipher_ctx *ctx,
		   struct drvcrypt_cipher_init *d_init)
{
	TEE_OperationMode mode = 0;

	if (d_init->encrypt)
		mode = TEE_MODE_ENCRYPT;
	else
		mode = TEE_MODE_DECRYPT;

	return ctx->sw_ctx->ops->init(ctx->sw_ctx, mode,
				      d_init->key1.data, d_init->key1.length,
				      NULL, 0,
				      d_init->iv.data, d_init->iv.length);
}

static TEE_Result __maybe_unused
asu_cipher_sw_alloc_ctx(struct asu_cipher_ctx *ctx, uint32_t algo)
{
	TEE_Result res = TEE_SUCCESS;

	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
		res = crypto_aes_ecb_alloc_ctx(&ctx->sw_ctx);
		break;
	case TEE_ALG_AES_CBC_NOPAD:
		res = crypto_aes_cbc_alloc_ctx(&ctx->sw_ctx);
		break;
	case TEE_ALG_AES_CTR:
		res = crypto_aes_ctr_alloc_ctx(&ctx->sw_ctx);
		break;
	default:
		res = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	if (res)
		EMSG("Failed to allocate software fallback context: %#"PRIx32,
		     res);

	return res;
}

/*
 * asu_cipher_free_ctx() - Free cipher context and release resources.
 * @ctx:	Cipher context to free
 */
static void asu_cipher_free_ctx(void *ctx)
{
	struct asu_cipher_ctx *asu_cipherctx = ctx;

	if (asu_cipherctx) {
		/* Always free software fallback context */
		if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK))
			asu_cipher_sw_free_ctx(asu_cipherctx);

		/* Always free unique ID (allocated in alloc_ctx) */
		if (asu_cipherctx->uniqueid != ASU_UNIQUE_ID_MAX)
			asu_free_unique_id(asu_cipherctx->uniqueid);

		asu_cipherctx->uniqueid = ASU_UNIQUE_ID_MAX;

		/* Clear sensitive material before freeing */
		memzero_explicit(asu_cipherctx->key,
				 sizeof(asu_cipherctx->key));
		memzero_explicit(asu_cipherctx->iv, sizeof(asu_cipherctx->iv));
		free(asu_cipherctx);
	}
}

/*
 * asu_cipher_copy_state() - Copy cipher context state from src to dst.
 * @dst_ctx:	Destination context to copy state into
 * @src_ctx:	Source context to copy state from
 *
 */
static void asu_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct asu_cipher_ctx *dst = dst_ctx;
	struct asu_cipher_ctx *src = src_ctx;

	if (!dst || !src)
		return;

	/* Copy software fallback state if using 192-bit key */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && src->use_sw_fallback) {
		asu_cipher_sw_copy_state(dst, src);
		dst->use_sw_fallback = src->use_sw_fallback;
		return;
	}

	/* Copy cipher operation state */
	dst->ciphermode = src->ciphermode;
	dst->optype = src->optype;
	dst->keysize = src->keysize;
	dst->hw_keysize = src->hw_keysize;
	dst->stream_offset = src->stream_offset;
	dst->use_sw_fallback = src->use_sw_fallback;

	/* Copy key material and IV - IV contains chaining state for CBC/CTR */
	memcpy(dst->key, src->key, sizeof(src->key));
	memcpy(dst->iv, src->iv, sizeof(src->iv));

	/* Copy saved keystream for CTR partial block continuation */
	memcpy(dst->keystream, src->keystream, sizeof(src->keystream));
}

/*
 * asu_cipher_send() - Send cipher command to ASU firmware via IPI.
 * @d_ctx:	Private cipher context
 * @cp:		Cipher operation command structure with parameters
 *
 * Return: TEE_SUCCESS or TEE_ERROR_GENERIC
 */
static TEE_Result asu_cipher_send(struct asu_cipher_ctx *d_ctx,
				  struct asu_cipher_op_cmd *cp)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t header = 0;
	uint32_t status = 0;

	header = asu_create_header(ASU_CIPHER_OPERATION_CMD_ID,
				   d_ctx->uniqueid,
				   ASU_MODULE_AES_ID,
				   sizeof(*cp) / sizeof(uint32_t));

	ret = asu_update_queue_buffer_n_send_ipi(&d_ctx->cparam, cp,
						 sizeof(*cp), header,
						 &status);
	if (!ret && status) {
		EMSG("FW error status=0x%"PRIx32, status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

/*
 * asu_cipher_final() - Finalize the cipher operation.
 * @ctx:	Cipher context
 */
static void asu_cipher_final(void *ctx)
{
	struct asu_cipher_ctx *asu_cipherctx = ctx;

	if (!asu_cipherctx)
		return;

	/* Call software fallback final if using 192-bit key */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) &&
	    asu_cipherctx->use_sw_fallback)
		asu_cipher_sw_final(asu_cipherctx);
}

/*
 * asu_cipher_ecb_update() - ECB mode cipher operation.
 * @asu_cipherctx:	Private cipher context
 * @src:		Input data buffer
 * @dst:		Output data buffer
 * @len:		Data length in bytes (must be block-aligned)
 *
 * Return: TEE_SUCCESS or error code.
 */
static TEE_Result asu_cipher_ecb_update(struct asu_cipher_ctx *asu_cipherctx,
					uint8_t *src, uint8_t *dst,
					uint32_t len)
{
	struct asu_cipher_op_cmd op = { };
	struct asu_cipher_key_object *kobj = NULL;
	size_t cacheline_len = dcache_get_line_size();
	uint8_t *dma_src = NULL;
	uint8_t *dma_dst = NULL;
	uint32_t remaining = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (len % ASU_CIPHER_BLOCK_SIZE != 0) {
		DMSG("ECB: Data length must be block-aligned");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dma_src = memalign(cacheline_len, ASU_CIPHER_DATA_CHUNK_LEN);
	dma_dst = memalign(cacheline_len, ASU_CIPHER_DATA_CHUNK_LEN);
	if (!dma_src || !dma_dst) {
		EMSG("ECB: Failed to allocate DMA buffers");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	kobj = &asu_cipherctx->key_obj;
	kobj->keyaddr = virt_to_phys(asu_cipherctx->key);
	kobj->keysize = asu_cipherctx->hw_keysize;
	kobj->keysrc = ASU_CIPHER_USER_KEY_0;
	kobj->keyid = 0;

	cache_operation(TEE_CACHEFLUSH, asu_cipherctx->key,
			asu_cipherctx->keysize);
	cache_operation(TEE_CACHEFLUSH, kobj, sizeof(*kobj));

	op.keyobjectaddr = virt_to_phys(kobj);
	op.enginemode = ASU_CIPHER_ECB_MODE;
	op.operationtype = asu_cipherctx->optype;
	op.operationflags = ASU_CIPHER_INIT | ASU_CIPHER_UPDATE |
			    ASU_CIPHER_FINAL;
	op.islast = 1;

	remaining = len;
	while (remaining) {
		op.datalen = MIN(remaining, ASU_CIPHER_DATA_CHUNK_LEN);

		memcpy(dma_src, src, op.datalen);
		cache_operation(TEE_CACHEFLUSH, dma_src, op.datalen);
		cache_operation(TEE_CACHEFLUSH, dma_dst, op.datalen);

		op.inputdataaddr = virt_to_phys(dma_src);
		op.outputdataaddr = virt_to_phys(dma_dst);

		asu_cipherctx->cparam.priority = ASU_PRIORITY_HIGH;
		ret = asu_cipher_send(asu_cipherctx, &op);
		if (ret) {
			EMSG("ECB: FW send failed");
			break;
		}

		cache_operation(TEE_CACHEINVALIDATE, dma_dst, op.datalen);
		memcpy(dst, dma_dst, op.datalen);

		src += op.datalen;
		dst += op.datalen;
		remaining -= op.datalen;
	}

out:
	free(dma_src);
	free(dma_dst);
	return ret;
}

/*
 * asu_cipher_cbc_update() - CBC mode cipher operation.
 * @asu_cipherctx:	Private cipher context
 * @src:		Input data buffer
 * @dst:		Output data buffer
 * @len:		Data length in bytes (must be block-aligned)
 *
 * Return: TEE_SUCCESS or error code.
 */
static TEE_Result asu_cipher_cbc_update(struct asu_cipher_ctx *asu_cipherctx,
					uint8_t *src, uint8_t *dst,
					uint32_t len)
{
	struct asu_cipher_op_cmd op = {};
	struct asu_cipher_key_object *kobj = NULL;
	size_t cacheline_len = dcache_get_line_size();
	uint8_t *dma_src = NULL;
	uint8_t *dma_dst = NULL;
	uint32_t remaining = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (len % ASU_CIPHER_BLOCK_SIZE != 0) {
		DMSG("CBC: Data length must be block-aligned");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dma_src = memalign(cacheline_len, ASU_CIPHER_DATA_CHUNK_LEN);
	dma_dst = memalign(cacheline_len, ASU_CIPHER_DATA_CHUNK_LEN);
	if (!dma_src || !dma_dst) {
		EMSG("CBC: Failed to allocate DMA buffers");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	kobj = &asu_cipherctx->key_obj;
	kobj->keyaddr = virt_to_phys(asu_cipherctx->key);
	kobj->keysize = asu_cipherctx->hw_keysize;
	kobj->keysrc = ASU_CIPHER_USER_KEY_0;
	kobj->keyid = 0;

	cache_operation(TEE_CACHEFLUSH, asu_cipherctx->key,
			asu_cipherctx->keysize);
	cache_operation(TEE_CACHEFLUSH, asu_cipherctx->iv,
			ASU_CIPHER_BLOCK_SIZE);
	cache_operation(TEE_CACHEFLUSH, kobj, sizeof(*kobj));

	op.keyobjectaddr = virt_to_phys(kobj);
	op.enginemode = ASU_CIPHER_CBC_MODE;
	op.operationtype = asu_cipherctx->optype;
	op.ivaddr = virt_to_phys(asu_cipherctx->iv);
	op.ivlen = ASU_CIPHER_BLOCK_SIZE;
	op.operationflags = ASU_CIPHER_INIT | ASU_CIPHER_UPDATE |
			    ASU_CIPHER_FINAL;
	op.islast = 1;

	remaining = len;
	while (remaining) {
		op.datalen = MIN(remaining, ASU_CIPHER_DATA_CHUNK_LEN);

		memcpy(dma_src, src, op.datalen);
		cache_operation(TEE_CACHEFLUSH, dma_src, op.datalen);
		cache_operation(TEE_CACHEFLUSH, dma_dst, op.datalen);

		op.inputdataaddr = virt_to_phys(dma_src);
		op.outputdataaddr = virt_to_phys(dma_dst);

		asu_cipherctx->cparam.priority = ASU_PRIORITY_HIGH;
		ret = asu_cipher_send(asu_cipherctx, &op);
		if (ret) {
			EMSG("CBC: FW send failed");
			break;
		}

		cache_operation(TEE_CACHEINVALIDATE, dma_dst, op.datalen);
		memcpy(dst, dma_dst, op.datalen);

		if (asu_cipherctx->optype == ASU_CIPHER_ENCRYPT_OPERATION) {
			memcpy(asu_cipherctx->iv,
			       dma_dst + op.datalen - ASU_CIPHER_BLOCK_SIZE,
			       ASU_CIPHER_BLOCK_SIZE);
		} else {
			memcpy(asu_cipherctx->iv,
			       dma_src + op.datalen - ASU_CIPHER_BLOCK_SIZE,
			       ASU_CIPHER_BLOCK_SIZE);
		}
		cache_operation(TEE_CACHEFLUSH, asu_cipherctx->iv,
				ASU_CIPHER_BLOCK_SIZE);

		src += op.datalen;
		dst += op.datalen;
		remaining -= op.datalen;
	}

out:
	free(dma_src);
	free(dma_dst);
	return ret;
}

/*
 * asu_cipher_ctr_inc_counter() - Increment 128-bit big-endian CTR IV by inc.
 * @ctr:	IV as two 64-bit big-endian words (ctr[0]=bytes 0-7,
 *		ctr[1]=bytes 8-15)
 * @inc:	Number of blocks to increment
 *
 * Performs full 128-bit increment with carry. Used as SW workaround since ASU
 * HW only increments bytes 12-15 with no carry into bytes 8-11.
 */
static void asu_cipher_ctr_inc_counter(uint64_t *ctr, uint32_t inc)
{
	uint64_t v0 = TEE_U64_FROM_BIG_ENDIAN(ctr[0]);
	uint64_t v1 = TEE_U64_FROM_BIG_ENDIAN(ctr[1]);
	uint64_t low = 0;

	low = v1;
	if (ADD_OVERFLOW(v1, inc, &low)) {
		low = v1 + inc;
		v0 = v0 + 1;
	}
	ctr[0] = TEE_U64_TO_BIG_ENDIAN(v0);
	ctr[1] = TEE_U64_TO_BIG_ENDIAN(low);
}

/*
 * asu_cipher_ctr_blocks_until_overflow() - Blocks before 32-bit counter wraps.
 * @ctr:	Current IV as two 64-bit big-endian words
 *
 * Returns blocks before bytes 12-15 overflow (needs SW carry);
 * UINT32_MAX if ctr32=0.
 */
static uint64_t asu_cipher_ctr_blocks_until_overflow(uint64_t *ctr)
{
	uint32_t ctr32 = TEE_U64_FROM_BIG_ENDIAN(ctr[1]);
	uint64_t avail = (~ctr32) + ASU_CIPHER_CTR32_WRAP_INCREMENT;

	return avail;
}

/*
 * asu_cipher_ctr_send_chunk() - Flush, send one CTR chunk, and copy output.
 * @ctx:	Private cipher context
 * @op:		Pre-filled command template
 * @dma_src:	DMA-aligned source buffer (already filled by caller)
 * @dma_dst:	DMA-aligned destination buffer
 * @dst:	Output buffer to copy result into
 * @len:	Byte length to process (must be <= ASU_CIPHER_DATA_CHUNK_LEN)
 *
 * Return: TEE_SUCCESS or error code.
 */
static TEE_Result asu_cipher_ctr_send_chunk(struct asu_cipher_ctx *ctx,
					    struct asu_cipher_op_cmd *op,
					    uint8_t *dma_src, uint8_t *dma_dst,
					    uint8_t *dst, uint32_t len)
{
	TEE_Result ret = TEE_SUCCESS;

	op->datalen = len;
	cache_operation(TEE_CACHEFLUSH, ctx->iv, ASU_CIPHER_BLOCK_SIZE);
	cache_operation(TEE_CACHEFLUSH, dma_src, len);
	cache_operation(TEE_CACHEFLUSH, dma_dst, len);
	op->inputdataaddr = virt_to_phys(dma_src);
	op->outputdataaddr = virt_to_phys(dma_dst);
	ctx->cparam.priority = ASU_PRIORITY_HIGH;
	ret = asu_cipher_send(ctx, op);
	if (ret) {
		EMSG("CTR: FW send failed");
		return ret;
	}
	cache_operation(TEE_CACHEINVALIDATE, dma_dst, len);
	memcpy(dst, dma_dst, len);
	return TEE_SUCCESS;
}

/*
 * asu_cipher_ctr_update() - CTR mode cipher operation with streaming support.
 * @ctx:	Private cipher context
 * @src:	Input data buffer
 * @dst:	Output data buffer
 * @len:	Data length in bytes (can be non-block-aligned)
 *
 * Checks 32-bit overflow once to compute the first segment length. The outer
 * loop runs at most twice (before and after the boundary); the inner loop
 * chunks each segment into DMA_CHUNK_LEN pieces.
 *
 * Return: TEE_SUCCESS or error code.
 */
static TEE_Result asu_cipher_ctr_update(struct asu_cipher_ctx *ctx,
					uint8_t *src, uint8_t *dst,
					uint32_t len)
{
	struct asu_cipher_op_cmd op = {};
	struct asu_cipher_key_object *kobj = NULL;
	size_t cacheline_len = dcache_get_line_size();
	uint8_t *dma_src = NULL;
	uint8_t *dma_dst = NULL;
	uint32_t process_len = 0;
	uint32_t num_blocks = 0;
	uint32_t seg_blocks = 0;
	uint32_t remaining_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!len)
		return TEE_SUCCESS;

	/* Use leftover keystream from previous call */
	while (ctx->stream_offset > 0 && len > 0) {
		*dst = *src ^ ctx->keystream[ctx->stream_offset];
		dst++;
		src++;
		len--;
		ctx->stream_offset++;
		if (ctx->stream_offset >= ASU_CIPHER_BLOCK_SIZE)
			ctx->stream_offset = 0;
	}

	if (!len)
		return TEE_SUCCESS;

	/* Setup for hardware processing */
	dma_src = memalign(cacheline_len, ASU_CIPHER_DATA_CHUNK_LEN);
	dma_dst = memalign(cacheline_len, ASU_CIPHER_DATA_CHUNK_LEN);
	if (!dma_src || !dma_dst) {
		EMSG("CTR: Failed to allocate DMA buffers");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Setup key object */
	kobj = &ctx->key_obj;
	kobj->keyaddr = virt_to_phys(ctx->key);
	kobj->keysize = ctx->hw_keysize;
	kobj->keysrc = ASU_CIPHER_USER_KEY_0;
	kobj->keyid = 0;

	cache_operation(TEE_CACHEFLUSH, ctx->key, ctx->keysize);
	cache_operation(TEE_CACHEFLUSH, kobj, sizeof(*kobj));

	/* Setup fixed command fields */
	op.keyobjectaddr = virt_to_phys(kobj);
	op.enginemode = ASU_CIPHER_CTR_MODE;
	op.operationtype = ctx->optype;
	op.ivaddr = virt_to_phys(ctx->iv);
	op.ivlen = ASU_CIPHER_BLOCK_SIZE;
	op.operationflags = ASU_CIPHER_INIT | ASU_CIPHER_UPDATE |
			    ASU_CIPHER_FINAL;
	op.islast = 1;

	/*
	 * Check 32-bit overflow once (very unlikely). Limit first segment to
	 * blocks_until_overflow blocks. Outer loop runs at most twice: first
	 * segment up to the boundary, then remaining blocks after SW carry.
	 */
	seg_blocks = MIN(len / ASU_CIPHER_BLOCK_SIZE,
			 asu_cipher_ctr_blocks_until_overflow(ctx->iv));
	remaining_len = len;
	while (seg_blocks > 0) {
		/* Inner loop: chunk seg_blocks into
		 * DMA_CHUNK_LEN sized pieces
		 */
		while (seg_blocks > 0) {
			num_blocks = MIN(seg_blocks, ASU_CIPHER_DATA_CHUNK_LEN /
					 ASU_CIPHER_BLOCK_SIZE);
			process_len = num_blocks * ASU_CIPHER_BLOCK_SIZE;
			memcpy(dma_src, src, process_len);
			ret = asu_cipher_ctr_send_chunk(ctx, &op, dma_src,
							dma_dst, dst,
							process_len);
			if (ret)
				goto out;
			asu_cipher_ctr_inc_counter(ctx->iv, num_blocks);
			src += process_len;
			dst += process_len;
			remaining_len -= process_len;
			seg_blocks -= num_blocks;
		}

		/* Remaining full blocks after roll over */
		seg_blocks = remaining_len / ASU_CIPHER_BLOCK_SIZE;
	}

	/* Handle partial (sub-block) tail */
	if (remaining_len > 0) {
		memzero_explicit(dma_src, ASU_CIPHER_BLOCK_SIZE);
		memcpy(dma_src, src, remaining_len);
		ret = asu_cipher_ctr_send_chunk(ctx, &op, dma_src, dma_dst,
						dst, ASU_CIPHER_BLOCK_SIZE);
		if (ret)
			goto out;
		/* Save keystream bytes not yet consumed for next call */
		memcpy(ctx->keystream + remaining_len, dma_dst + remaining_len,
		       ASU_CIPHER_BLOCK_SIZE - remaining_len);
		ctx->stream_offset = (uint8_t)remaining_len;
		asu_cipher_ctr_inc_counter(ctx->iv, ASU_CIPHER_CTR_INCREMENT);
	}

out:
	free(dma_src);
	free(dma_dst);
	return ret;
}

/*
 * asu_cipher_update() - Perform cipher operation via ASU firmware.
 * @asu_cipherctx:	Private cipher context
 * @src:		Input data buffer
 * @dst:		Output data buffer
 * @len:		Data length in bytes
 *
 * Dispatches to mode-specific update functions for easier debugging.
 *
 * Return: TEE_SUCCESS or error code.
 */
static TEE_Result asu_cipher_update(struct asu_cipher_ctx *asu_cipherctx,
				    uint8_t *src, uint8_t *dst, uint32_t len)
{
	switch (asu_cipherctx->ciphermode) {
	case ASU_CIPHER_ECB_MODE:
		return asu_cipher_ecb_update(asu_cipherctx, src, dst, len);
	case ASU_CIPHER_CBC_MODE:
		return asu_cipher_cbc_update(asu_cipherctx, src, dst, len);
	case ASU_CIPHER_CTR_MODE:
		return asu_cipher_ctr_update(asu_cipherctx, src, dst, len);
	default:
		DMSG("Unsupported mode: 0x%"PRIx32, asu_cipherctx->ciphermode);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result asu_cipher_do_update(struct drvcrypt_cipher_update *d_update)
{
	struct asu_cipher_ctx *asu_cipherctx = d_update->ctx;

	if (!d_update->src.data || !d_update->dst.data ||
	    !d_update->src.length) {
		DMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Use software fallback for 192-bit keys */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) &&
	    asu_cipherctx->use_sw_fallback)
		return asu_cipher_sw_update(asu_cipherctx, d_update->last,
					    d_update->src.data,
					    d_update->src.length,
					    d_update->dst.data);

	return asu_cipher_update(asu_cipherctx, d_update->src.data,
				 d_update->dst.data, d_update->src.length);
}

/*
 * asu_cipher_initialize() - Initialize cipher context with key and IV.
 * @d_init:	Cipher initialization data from caller
 *
 * Return: TEE_SUCCESS or TEE_ERROR_BAD_PARAMETERS
 */
static TEE_Result asu_cipher_initialize(struct drvcrypt_cipher_init *d_init)
{
	struct asu_cipher_ctx *asu_cipherctx = NULL;
	size_t key_len = 0;
	TEE_Result res = TEE_SUCCESS;

	asu_cipherctx = d_init->ctx;
	key_len = d_init->key1.length;

	if (!d_init->key1.data) {
		DMSG("Invalid key: NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && key_len == AES_KEYSIZE_192) {
		res = asu_cipher_sw_init(asu_cipherctx, d_init);
		if (res) {
			EMSG("Software cipher init failed: %#"PRIx32, res);
			return res;
		}

		asu_cipherctx->use_sw_fallback = true;
		asu_cipherctx->keysize = key_len;
		return TEE_SUCCESS;
	}

	/* ASU hardware only supports 128-bit and 256-bit AES keys */
	if (key_len == AES_KEYSIZE_128) {
		asu_cipherctx->hw_keysize = ASU_CIPHER_KEY_SIZE_128_BITS;
		asu_cipherctx->use_sw_fallback = false;
	} else if (key_len == AES_KEYSIZE_256) {
		asu_cipherctx->hw_keysize = ASU_CIPHER_KEY_SIZE_256_BITS;
		asu_cipherctx->use_sw_fallback = false;
	} else {
		DMSG("Unsupported key size: %zu", key_len);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	memcpy(asu_cipherctx->key, d_init->key1.data, key_len);
	asu_cipherctx->keysize = key_len;

	if (asu_cipherctx->ciphermode == ASU_CIPHER_ECB_MODE) {
		memset(asu_cipherctx->iv, 0, ASU_CIPHER_BLOCK_SIZE);
	} else if (d_init->iv.data && d_init->iv.length > 0 &&
		   d_init->iv.length <= ASU_CIPHER_BLOCK_SIZE) {
		memcpy(asu_cipherctx->iv, d_init->iv.data, d_init->iv.length);
	}

	if (d_init->encrypt)
		asu_cipherctx->optype = ASU_CIPHER_ENCRYPT_OPERATION;
	else
		asu_cipherctx->optype = ASU_CIPHER_DECRYPT_OPERATION;

	/* Reset CTR streaming state */
	asu_cipherctx->stream_offset = 0;
	memset(asu_cipherctx->keystream, 0,
	       sizeof(asu_cipherctx->keystream));

	return TEE_SUCCESS;
}

/*
 * asu_cipher_alloc_ctx() - Allocate Private cipher context.
 * @ctx:	Crypto context used in cipher operations
 * @algo:	Cipher algorithm type
 *
 * Return: TEE_SUCCESS, TEE_ERROR_NOT_IMPLEMENTED, TEE_ERROR_OUT_OF_MEMORY
 */
static TEE_Result asu_cipher_alloc_ctx(void **ctx, uint32_t algo)
{
	struct asu_cipher_ctx *asu_cipherctx = NULL;
	uint32_t aesmode = 0;
	TEE_Result res = TEE_SUCCESS;

	res = asu_cipher_get_cipher_mode(algo, &aesmode);
	if (res)
		return res;

	asu_cipherctx = calloc(1, sizeof(*asu_cipherctx));
	if (!asu_cipherctx) {
		EMSG("Failed to allocate ASU cipher context");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	asu_cipherctx->ciphermode = aesmode;
	asu_cipherctx->uniqueid = asu_alloc_unique_id();

	/*
	 * Intentionally return TEE_ERROR_NOT_IMPLEMENTED when hardware is
	 * busy to trigger drvcrypt software fallback. Returning
	 * TEE_ERROR_BUSY would fail the operation without fallback.
	 */

	if (asu_cipherctx->uniqueid == ASU_UNIQUE_ID_MAX) {
		DMSG("All unique ID in use. Fallback to SW");
		free(asu_cipherctx);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	*ctx = asu_cipherctx;

	/* Pre-allocate software fallback context */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK)) {
		res = asu_cipher_sw_alloc_ctx(asu_cipherctx, algo);
		if (res) {
			EMSG("SW fallback alloc failed: %#"PRIx32, res);
			asu_free_unique_id(asu_cipherctx->uniqueid);
			free(asu_cipherctx);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static struct drvcrypt_cipher asu_cipher_op = {
	.alloc_ctx = asu_cipher_alloc_ctx,
	.init = asu_cipher_initialize,
	.update = asu_cipher_do_update,
	.final = asu_cipher_final,
	.copy_state = asu_cipher_copy_state,
	.free_ctx = asu_cipher_free_ctx,
};

static TEE_Result asu_cipher_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_cipher(&asu_cipher_op);
	if (ret)
		EMSG("ASU Cipher register failed ret=%#"PRIx32, ret);

	return ret;
}

driver_init(asu_cipher_init);
