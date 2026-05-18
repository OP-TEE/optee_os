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
#include <malloc.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <string.h>
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

/**
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
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

/*
 * Software fallback functions for 192-bit key support
 */
#ifdef CFG_AMD_ASU_SW_FALLBACK
static void asu_cipher_sw_free_ctx(struct asu_cipher_ctx *ctx)
{
	if (ctx->sw_ctx) {
		ctx->sw_ctx->ops->free_ctx(ctx->sw_ctx);
		ctx->sw_ctx = NULL;
	}
}

static void asu_cipher_sw_copy_state(struct asu_cipher_ctx *dst,
				     struct asu_cipher_ctx *src)
{
		src->sw_ctx->ops->copy_state(dst->sw_ctx, src->sw_ctx);
}

static void asu_cipher_sw_final(struct asu_cipher_ctx *ctx)
{
		ctx->sw_ctx->ops->final(ctx->sw_ctx);
}

static TEE_Result asu_cipher_sw_update(struct asu_cipher_ctx *ctx,
				       bool last, uint8_t *src,
				       size_t len, uint8_t *dst)
{
	return ctx->sw_ctx->ops->update(ctx->sw_ctx, last, src, len, dst);
}

static TEE_Result asu_cipher_sw_init(struct asu_cipher_ctx *ctx,
				     struct drvcrypt_cipher_init *d_init)
{
	TEE_OperationMode mode;

	mode = d_init->encrypt ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT;

	return ctx->sw_ctx->ops->init(ctx->sw_ctx, mode,
				      d_init->key1.data, d_init->key1.length,
				      NULL, 0,
				      d_init->iv.data, d_init->iv.length);
}

static TEE_Result asu_cipher_sw_alloc_ctx(struct asu_cipher_ctx *ctx,
					  uint32_t algo)
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
		EMSG("Failed to allocate software fallback context: %#x", res);

	return res;
}
#endif /* CFG_AMD_ASU_SW_FALLBACK */

/**
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
		memset(asu_cipherctx->key, 0, sizeof(asu_cipherctx->key));
		memset(asu_cipherctx->iv, 0, sizeof(asu_cipherctx->iv));
		free(asu_cipherctx);
	}
}

/**
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

/**
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
	uint32_t status = TEE_ERROR_GENERIC;

	header = asu_create_header(ASU_CIPHER_OPERATION_CMD_ID,
				   d_ctx->uniqueid,
				   ASU_MODULE_CIPHER_ID,
				   sizeof(*cp) / sizeof(uint32_t));

	ret = asu_update_queue_buffer_n_send_ipi(&d_ctx->cparam, cp,
						 sizeof(*cp), header,
						 &status);
	if (status) {
		EMSG("FW error status=0x%x", status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

/**
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

/**
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
	struct asu_cipher_op_cmd op = {};
	struct asu_cipher_key_object *kobj = NULL;
	uint8_t *dma_src = NULL;
	uint8_t *dma_dst = NULL;
	uint32_t remaining = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (len % ASU_CIPHER_BLOCK_SIZE != 0) {
		EMSG("ECB: Data length must be block-aligned");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dma_src = memalign(64, ASU_CIPHER_DATA_CHUNK_LEN);
	dma_dst = memalign(64, ASU_CIPHER_DATA_CHUNK_LEN);
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

/**
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
	uint8_t *dma_src = NULL;
	uint8_t *dma_dst = NULL;
	uint32_t remaining = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (len % ASU_CIPHER_BLOCK_SIZE != 0) {
		EMSG("CBC: Data length must be block-aligned");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dma_src = memalign(64, ASU_CIPHER_DATA_CHUNK_LEN);
	dma_dst = memalign(64, ASU_CIPHER_DATA_CHUNK_LEN);
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
		remaining -= op.datalen;

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
	}

out:
	free(dma_src);
	free(dma_dst);
	return ret;
}

/**
 * asu_cipher_ctr_inc_counter() - Increment CTR counter (big-endian) by inc.
 * @ctr:	16-byte counter array (treated as two 64-bit big-endian values)
 * @inc:	Value to increment counter by
 *
 */
static void asu_cipher_ctr_inc_counter(uint64_t *ctr, uint32_t inc)
{
	uint64_t v0 = TEE_U64_FROM_BIG_ENDIAN(ctr[0]);
	uint64_t v1 = TEE_U64_FROM_BIG_ENDIAN(ctr[1]);

	/* Increment counter */
	if (ADD_OVERFLOW(v1, inc, &v1))
		v0++;

	ctr[0] = TEE_U64_TO_BIG_ENDIAN(v0);
	ctr[1] = TEE_U64_TO_BIG_ENDIAN(v1);
}

/**
 * asu_cipher_ctr_update() - CTR mode cipher operation with streaming support.
 * @ctx:	Private cipher context
 * @src:	Input data buffer
 * @dst:	Output data buffer
 * @len:	Data length in bytes (can be non-block-aligned)
 *
 * Return: TEE_SUCCESS or error code.
 */
static TEE_Result asu_cipher_ctr_update(struct asu_cipher_ctx *ctx,
					uint8_t *src, uint8_t *dst,
					uint32_t len)
{
	struct asu_cipher_op_cmd op = {};
	struct asu_cipher_key_object *kobj = NULL;
	uint8_t *dma_src = NULL;
	uint8_t *dma_dst = NULL;
	uint32_t process_len = 0;
	uint32_t num_blocks = 0;
	uint32_t i = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (len == 0)
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

	/* All data processed using saved keystream? Done! */
	if (len == 0)
		return TEE_SUCCESS;

	/* Setup for hardware processing */
	dma_src = memalign(64, ASU_CIPHER_DATA_CHUNK_LEN);
	dma_dst = memalign(64, ASU_CIPHER_DATA_CHUNK_LEN);
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

	/* Process all data (full blocks and partial block) */
	while (len > 0) {
		cache_operation(TEE_CACHEFLUSH, ctx->iv, ASU_CIPHER_BLOCK_SIZE);

		if (len >= ASU_CIPHER_BLOCK_SIZE) {
			/* Full blocks: process up to chunk size */
			process_len = MIN(len, ASU_CIPHER_DATA_CHUNK_LEN);
			process_len = (process_len / ASU_CIPHER_BLOCK_SIZE) *
				      ASU_CIPHER_BLOCK_SIZE;
			memcpy(dma_src, src, process_len);
			op.datalen = process_len;
		} else {
			/* Partial block: pad with zeros */
			process_len = len;
			memset(dma_src, 0, ASU_CIPHER_BLOCK_SIZE);
			memcpy(dma_src, src, len);
			op.datalen = ASU_CIPHER_BLOCK_SIZE;
		}

		cache_operation(TEE_CACHEFLUSH, dma_src, op.datalen);
		cache_operation(TEE_CACHEFLUSH, dma_dst, op.datalen);

		op.inputdataaddr = virt_to_phys(dma_src);
		op.outputdataaddr = virt_to_phys(dma_dst);

		ctx->cparam.priority = ASU_PRIORITY_HIGH;
		ret = asu_cipher_send(ctx, &op);
		if (ret) {
			EMSG("CTR: FW send failed");
			goto out;
		}

		cache_operation(TEE_CACHEINVALIDATE, dma_dst, op.datalen);

		if (len >= ASU_CIPHER_BLOCK_SIZE) {
			/* Full blocks: copy output and increment counter */
			memcpy(dst, dma_dst, process_len);
			num_blocks = process_len / ASU_CIPHER_BLOCK_SIZE;

			/* Increment counter by number of blocks processed */
			asu_cipher_ctr_inc_counter(ctx->iv, num_blocks);
		} else {
			/* Partial block: save keystream for next call */
			memcpy(dst, dma_dst, len);
			for (i = 0; i < ASU_CIPHER_BLOCK_SIZE; i++)
				ctx->keystream[i] = dma_dst[i] ^ dma_src[i];
			ctx->stream_offset = len;
			asu_cipher_ctr_inc_counter(ctx->iv, 1);
		}

		src += process_len;
		dst += process_len;
		len -= process_len;
	}

out:
	free(dma_src);
	free(dma_dst);
	return ret;
}

/**
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
		EMSG("Unsupported mode: 0x%x", asu_cipherctx->ciphermode);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result asu_cipher_do_update(struct drvcrypt_cipher_update *d_update)
{
	struct asu_cipher_ctx *asu_cipherctx = d_update->ctx;

	if (!d_update->src.data || !d_update->dst.data ||
	    !d_update->src.length) {
		EMSG("Invalid input parameters");
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

/**
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
		EMSG("Invalid key: NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* ASU hardware only supports 128-bit and 256-bit AES keys */
	if (key_len == AES_KEYSIZE_128) {
		asu_cipherctx->hw_keysize = ASU_CIPHER_KEY_SIZE_128_BITS;
		asu_cipherctx->use_sw_fallback = false;
	} else if (key_len == AES_KEYSIZE_256) {
		asu_cipherctx->hw_keysize = ASU_CIPHER_KEY_SIZE_256_BITS;
		asu_cipherctx->use_sw_fallback = false;
	} else if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) &&
		   key_len == AES_KEYSIZE_192) {
		res = asu_cipher_sw_init(asu_cipherctx, d_init);
		if (res) {
			EMSG("Software cipher init failed: %#x", res);
			return res;
		}

		asu_cipherctx->use_sw_fallback = true;
		asu_cipherctx->keysize = key_len;
		return TEE_SUCCESS;
	}
	if (key_len != AES_KEYSIZE_128 && key_len != AES_KEYSIZE_256) {
		EMSG("Unsupported key size: %zu", key_len);
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
	memset(asu_cipherctx->keystream, 0, sizeof(asu_cipherctx->keystream));

	return TEE_SUCCESS;
}

/**
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
		return TEE_ERROR_NOT_IMPLEMENTED;

	asu_cipherctx = calloc(1, sizeof(*asu_cipherctx));
	if (!asu_cipherctx) {
		EMSG("Failed to allocate ASU cipher context");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	asu_cipherctx->ciphermode = aesmode;
	asu_cipherctx->sw_ctx = NULL;
	asu_cipherctx->use_sw_fallback = false;
	asu_cipherctx->uniqueid = asu_alloc_unique_id();
	if (asu_cipherctx->uniqueid == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to get unique ID");
		free(asu_cipherctx);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	*ctx = asu_cipherctx;

	/* Pre-allocate software fallback context */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK)) {
		res = asu_cipher_sw_alloc_ctx(asu_cipherctx, algo);
		if (res) {
			EMSG("SW fallback alloc failed: %#x", res);
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
		EMSG("ASU Cipher register failed ret=%#x", ret);

	return ret;
}

driver_init(asu_cipher_init);
