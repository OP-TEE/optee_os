// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/amd/asu_client.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <string_ext.h>
#include <tee/cache.h>
#include <trace.h>
#include <util.h>

#define ASU_AES_OPERATION_CMD_ID	0U

/* AES operation flags */
#define ASU_AES_INIT			0x1U
#define ASU_AES_UPDATE			0x2U
#define ASU_AES_FINAL			0x4U

/* AES engine modes (from XASU_AES_*_MODE) */
#define ASU_AES_GCM_MODE		0x6U
#define ASU_AES_CCM_MODE		0x5U

/* AES key parameters */
#define ASU_AES_USER_KEY_0		0x0U
#define ASU_AES_KEY_ID_0		0x0U
#define ASU_AES_KEY_SIZE_128_BYTES	16U
#define ASU_AES_KEY_SIZE_192_BYTES	24U
#define ASU_AES_KEY_SIZE_256_BYTES	32U
#define ASU_AES_KEY_PARAM_128	0x0U
#define ASU_AES_KEY_PARAM_256	0x2U

/* AES operation types */
#define ASU_AES_ENCRYPT_OPERATION	0x0U
#define ASU_AES_DECRYPT_OPERATION	0x1U

/* AES size constants */
#define ASU_AES_BLOCK_SIZE		16U
#define ASU_AES_MAX_TAG_LEN		16U
#define ASU_AES_MAX_KEY_SIZE		32U
#define ASU_AES_MAX_NONCE_LEN		16U
#define ASU_AES_GCM_MIN_NONCE_LEN	1U
#define ASU_AES_CCM_MIN_NONCE_LEN	7U
#define ASU_AES_CCM_MAX_NONCE_LEN	13U

/* Tag length bounds */
#define ASU_CCM_MIN_TAG_LEN		4U
#define ASU_GCM_MIN_TAG_LEN		8U

/* Common field values */
#define ASU_AES_NOT_LAST		0U
#define ASU_AES_LAST			1U
#define ASU_AES_ODD_LENGTH_MASK		0x1U

/*
 * ASUFW composite status decoding.
 * The firmware returns a composite error word; the low 10 bits carry the
 * xasufw_status enum value (max 0x3FF).  All higher bits are module/layer
 * context and must be masked off before comparing against known codes.
 */
#define ASU_FW_STATUS_CODE_MASK		0x3FFU
#define ASU_FW_AES_TAG_COMPARE_FAILED	0x9AU

/* DMA alignment for buffers passed to firmware */
#define ASU_DMA_ALIGN			64U
#define ASU_AUTHENC_DATA_CHUNK_LEN	4096U
/* Keep tag DMA buffer at least one cache line for cache maintenance ops. */
#define ASU_AUTHENC_TAG_DMA_BUF_LEN	ASU_DMA_ALIGN

struct asu_aes_params {
	uint64_t input_data_addr;
	uint64_t output_data_addr;
	uint64_t aad_addr;
	uint64_t key_object_addr;
	uint64_t iv_addr;
	uint64_t tag_addr;
	uint32_t data_len;
	uint32_t aad_len;
	uint32_t iv_len;
	uint32_t tag_len;
	uint8_t mode;
	uint8_t operation_flags;
	uint8_t is_last;
	uint8_t operation_type;
	uint32_t iv_id;
};

struct asu_aes_key_object {
	uint64_t key_address;
	uint32_t key_size;
	uint32_t key_src;
	uint32_t key_id;
};

/* Global device state serialises HW IPI sends */
struct asu_authenc_dev {
	/* Serializes ASUFW IPI accesses across authenc sessions */
	struct mutex engine_lock;
	/* True when no authenc context is currently using the AES engine */
	bool aes_available;
};

/* Per-operation context */
struct asu_authenc_ctx {
	struct asu_client_params cparam;
	/* Inline key object and buffers (same model as asu_cipher_ctx) */
	struct asu_aes_key_object key_obj;
	size_t key_len;
	size_t nonce_len;
	size_t tag_len;
	size_t processed_aad_len;
	size_t total_aad_len;
	size_t total_plen;
	size_t processed_plen;
	/* Software fallback for 192-bit keys or non-aligned GCM AAD */
	bool use_sw_fallback;
	struct crypto_authenc_ctx *sw_ctx;
	uint8_t *key_buf;
	uint8_t *nonce_buf;
	uint8_t *src_dma_buf;
	uint8_t *dst_dma_buf;
	uint8_t mode;
	uint8_t operation_type;
	uint8_t uniqueid;
};

static struct asu_authenc_dev *asu_ae_dev;

/**
 * asu_authenc_get_mode() - Map TEE algorithm to ASU AES engine mode.
 * @algo:   TEE algorithm identifier
 * @mode:   Output engine mode
 *
 * Return: TEE_SUCCESS or TEE_ERROR_NOT_IMPLEMENTED
 */
static TEE_Result asu_authenc_get_mode(uint32_t algo, uint8_t *mode)
{
	switch (algo) {
	case TEE_ALG_AES_GCM:
		*mode = ASU_AES_GCM_MODE;
		return TEE_SUCCESS;
	case TEE_ALG_AES_CCM:
		*mode = ASU_AES_CCM_MODE;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/**
 * asu_aes_send() - Build header and send AES command to ASUFW.
 * @ctx:    Private authenc context
 * @params: AES params struct
 *
 * Return: TEE_SUCCESS or TEE_ERROR_GENERIC
 */
static TEE_Result asu_aes_send(struct asu_authenc_ctx *ctx,
			       struct asu_aes_params *params,
			       uint32_t *fw_status)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t header = 0;

	header = asu_create_header(ASU_AES_OPERATION_CMD_ID,
				   ctx->uniqueid, ASU_MODULE_AES_ID,
				   sizeof(*params) / sizeof(uint32_t));

	ret = asu_update_queue_buffer_n_send_ipi(&ctx->cparam, params,
						 sizeof(*params), header,
						 fw_status);

	if (*fw_status) {
		EMSG("ASUFW AES error status=0x%x", *fw_status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

/**
 * asu_authenc_set_init_params() - Set INIT-phase parameters in AES params.
 * @ae_ctx: Private authenc context
 * @params: AES params struct to populate
 *
 * Flushes key, key object, and nonce caches, then sets IV address/length,
 * key object address, engine mode, and adds ASU_AES_INIT to operation flags.
 */
static void asu_authenc_set_init_params(struct asu_authenc_ctx *ae_ctx,
					struct asu_aes_params *params)
{
	params->iv_addr = virt_to_phys(ae_ctx->nonce_buf);
	params->iv_len = ae_ctx->nonce_len;
	params->key_object_addr = virt_to_phys(&ae_ctx->key_obj);
	params->mode = ae_ctx->mode;
	params->operation_flags |= ASU_AES_INIT;
}

/*
 * Software fallback functions for 192-bit key support and
 * GCM with non-16-byte-aligned AAD.
 */
#ifdef CFG_AMD_ASU_SW_FALLBACK
static TEE_Result asu_authenc_sw_alloc_ctx(struct asu_authenc_ctx *ctx)
{
	TEE_Result res = TEE_SUCCESS;

	switch (ctx->mode) {
	case ASU_AES_GCM_MODE:
		res = crypto_aes_gcm_alloc_ctx(&ctx->sw_ctx);
		break;
	case ASU_AES_CCM_MODE:
		res = crypto_aes_ccm_alloc_ctx(&ctx->sw_ctx);
		break;
	default:
		res = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	if (res)
		EMSG("Failed to allocate SW authenc context: %#x", res);

	return res;
}

static void asu_authenc_sw_free_ctx(struct asu_authenc_ctx *ctx)
{
	if (ctx->sw_ctx) {
		ctx->sw_ctx->ops->free_ctx(ctx->sw_ctx);
		ctx->sw_ctx = NULL;
	}
}

static TEE_Result asu_authenc_sw_init(struct asu_authenc_ctx *ctx,
				      struct drvcrypt_authenc_init *dinit)
{
	TEE_OperationMode mode;

	mode = dinit->encrypt ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT;

	return ctx->sw_ctx->ops->init(ctx->sw_ctx, mode,
				      dinit->key.data, dinit->key.length,
				      dinit->nonce.data, dinit->nonce.length,
				      dinit->tag_len, dinit->aad_len,
				      dinit->payload_len);
}

static TEE_Result asu_authenc_sw_update_aad(struct asu_authenc_ctx *ctx,
					    const uint8_t *data, size_t len)
{
	return ctx->sw_ctx->ops->update_aad(ctx->sw_ctx, data, len);
}

static TEE_Result asu_authenc_sw_update_payload(struct asu_authenc_ctx *ctx,
						TEE_OperationMode mode,
						const uint8_t *src,
						size_t len, uint8_t *dst)
{
	return ctx->sw_ctx->ops->update_payload(ctx->sw_ctx, mode,
						src, len, dst);
}

static TEE_Result asu_authenc_sw_enc_final(struct asu_authenc_ctx *ctx,
					   const uint8_t *src, size_t len,
					   uint8_t *dst, uint8_t *tag,
					   size_t *tag_len)
{
	return ctx->sw_ctx->ops->enc_final(ctx->sw_ctx, src, len,
					   dst, tag, tag_len);
}

static TEE_Result asu_authenc_sw_dec_final(struct asu_authenc_ctx *ctx,
					   const uint8_t *src, size_t len,
					   uint8_t *dst, const uint8_t *tag,
					   size_t tag_len)
{
	return ctx->sw_ctx->ops->dec_final(ctx->sw_ctx, src, len,
					   dst, tag, tag_len);
}

static void asu_authenc_sw_final(struct asu_authenc_ctx *ctx)
{
	if (ctx->sw_ctx)
		ctx->sw_ctx->ops->final(ctx->sw_ctx);
}

#endif /* CFG_AMD_ASU_SW_FALLBACK */

/**
 * asu_authenc_alloc_ctx() - Allocate authenticated encryption context.
 * @ctx:  Output context pointer
 * @algo: TEE algorithm type
 *
 * Grabs the engine (mutex-protected availability flag) and allocates a
 * unique-id.
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_authenc_alloc_ctx(void **ctx, uint32_t algo)
{
	struct asu_authenc_ctx *ae_ctx = NULL;
	uint8_t mode = 0;
	TEE_Result ret = TEE_SUCCESS;

	ret = asu_authenc_get_mode(algo, &mode);
	if (ret)
		return ret;

	/*
	 * Intentionally returning TEE_ERROR_NOT_IMPLEMENTED when HW is busy
	 * to trigger drvcrypt software fallback. TEE_ERROR_BUSY would cause
	 * the operation to fail without fallback.
	 */
	mutex_lock(&asu_ae_dev->engine_lock);
	if (!asu_ae_dev->aes_available) {
		mutex_unlock(&asu_ae_dev->engine_lock);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	asu_ae_dev->aes_available = false;
	mutex_unlock(&asu_ae_dev->engine_lock);

	ae_ctx = calloc(1, sizeof(*ae_ctx));
	if (!ae_ctx) {
		EMSG("Failed to allocate authenc context");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_ctx;
	}
	/* Allocate DMA-aligned key buffer to avoid cache line conflicts */
	ae_ctx->key_buf = memalign(ASU_DMA_ALIGN, ASU_AES_MAX_KEY_SIZE);
	if (!ae_ctx->key_buf) {
		EMSG("Failed to allocate key buffer");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_ctx;
	}

	/* Allocate DMA-aligned nonce buffer to avoid cache line conflicts */
	ae_ctx->nonce_buf = memalign(ASU_DMA_ALIGN, ASU_AES_MAX_NONCE_LEN);
	if (!ae_ctx->nonce_buf) {
		EMSG("Failed to allocate nonce buffer");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_ctx;
	}

	/* Allocate reusable DMA-aligned data buffers */
	ae_ctx->src_dma_buf = memalign(ASU_DMA_ALIGN,
				       ASU_AUTHENC_DATA_CHUNK_LEN);
	if (!ae_ctx->src_dma_buf) {
		EMSG("Failed to allocate source DMA buffer");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_ctx;
	}

	ae_ctx->dst_dma_buf = memalign(ASU_DMA_ALIGN,
				       ASU_AUTHENC_DATA_CHUNK_LEN);
	if (!ae_ctx->dst_dma_buf) {
		EMSG("Failed to allocate destination DMA buffer");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_ctx;
	}

	ae_ctx->uniqueid = asu_alloc_unique_id();
	if (ae_ctx->uniqueid == ASU_UNIQUE_ID_MAX) {
		EMSG("Failed to get unique ID");
		ret = TEE_ERROR_BUSY;
		goto free_ctx;
	}

	ae_ctx->mode = mode;
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK)) {
		ret = asu_authenc_sw_alloc_ctx(ae_ctx);
		if (ret) {
			asu_free_unique_id(ae_ctx->uniqueid);
			goto free_ctx;
		}
	}

	*ctx = ae_ctx;
	return TEE_SUCCESS;

free_ctx:
	if (ae_ctx) {
		if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK))
			asu_authenc_sw_free_ctx(ae_ctx);
		free(ae_ctx->key_buf);
		free(ae_ctx->nonce_buf);
		free(ae_ctx->src_dma_buf);
		free(ae_ctx->dst_dma_buf);
	}
	mutex_lock(&asu_ae_dev->engine_lock);
	asu_ae_dev->aes_available = true;
	mutex_unlock(&asu_ae_dev->engine_lock);
	free(ae_ctx);
	return ret;
}

/**
 * asu_authenc_free_ctx() - Free context and release engine.
 * @ctx: Context to free
 */
static void asu_authenc_free_ctx(void *ctx)
{
	struct asu_authenc_ctx *ae_ctx = ctx;

	if (!ae_ctx)
		return;

	/* Free software fallback context (always pre-allocated in alloc_ctx) */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK))
		asu_authenc_sw_free_ctx(ae_ctx);

	asu_free_unique_id(ae_ctx->uniqueid);

	mutex_lock(&asu_ae_dev->engine_lock);
	assert(!asu_ae_dev->aes_available);
	asu_ae_dev->aes_available = true;
	mutex_unlock(&asu_ae_dev->engine_lock);

	/* Free DMA-aligned buffers */
	free(ae_ctx->key_buf);
	free(ae_ctx->nonce_buf);
	free(ae_ctx->src_dma_buf);
	free(ae_ctx->dst_dma_buf);
	free(ae_ctx);
}

/**
 * asu_authenc_init() - Initialize authenticated encryption operation.
 * @dinit: Initialization parameters (key, nonce, tag/aad/payload lengths)
 *
 * Sends INIT request to ASUFW with IV, key object, and total AAD/payload
 * lengths so that ASUFW can set up the operation context for both GCM and CCM.
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_authenc_init(struct drvcrypt_authenc_init *dinit)
{
	struct asu_authenc_ctx *ae_ctx = dinit->ctx;
	size_t key_len = 0;
	struct asu_aes_params params = {};
	uint32_t fw_status = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!ae_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Validate key */
	if (!dinit->key.data || !dinit->key.length)
		return TEE_ERROR_BAD_PARAMETERS;

	key_len = dinit->key.length;
	if (key_len != ASU_AES_KEY_SIZE_128_BYTES &&
	    key_len != ASU_AES_KEY_SIZE_192_BYTES &&
	    key_len != ASU_AES_KEY_SIZE_256_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Validate nonce */
	if (!dinit->nonce.data || !dinit->nonce.length)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ae_ctx->mode == ASU_AES_CCM_MODE) {
		if (dinit->nonce.length < ASU_AES_CCM_MIN_NONCE_LEN ||
		    dinit->nonce.length > ASU_AES_CCM_MAX_NONCE_LEN) {
			DMSG("Invalid CCM nonce length: %zu",
			     dinit->nonce.length);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		if (dinit->nonce.length < ASU_AES_GCM_MIN_NONCE_LEN ||
		    dinit->nonce.length > ASU_AES_MAX_NONCE_LEN) {
			DMSG("Invalid GCM nonce length: %zu",
			     dinit->nonce.length);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/* Validate tag length */
	if (ae_ctx->mode == ASU_AES_GCM_MODE) {
		if (dinit->tag_len < ASU_GCM_MIN_TAG_LEN ||
		    dinit->tag_len > ASU_AES_MAX_TAG_LEN) {
			DMSG("Invalid GCM tag length: %zu", dinit->tag_len);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else if (ae_ctx->mode == ASU_AES_CCM_MODE) {
		if (dinit->tag_len < ASU_CCM_MIN_TAG_LEN ||
		    dinit->tag_len > ASU_AES_MAX_TAG_LEN ||
		    (dinit->tag_len & ASU_AES_ODD_LENGTH_MASK)) {
			DMSG("Invalid CCM tag length: %zu", dinit->tag_len);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/* Reset fallback flag for context reuse */
	ae_ctx->use_sw_fallback = false;

	/*
	 * Software fallback for 192-bit keys (unsupported by ASUFW) or
	 * GCM with non-16-byte-aligned AAD length.
	 */

	if (key_len == ASU_AES_KEY_SIZE_192_BYTES ||
	    (ae_ctx->mode == ASU_AES_GCM_MODE &&
	     (dinit->aad_len % ASU_AES_BLOCK_SIZE) != 0)) {
		/* SW fallback is needed, check if it's explicitly enabled */
		if (!IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK)) {
			DMSG("SW fallback is not enabled");
			return TEE_ERROR_NOT_SUPPORTED;
		}

		ret = asu_authenc_sw_init(ae_ctx, dinit);
		if (ret)
			return ret;
		ae_ctx->use_sw_fallback = true;
		return ret;
	}

	/* Copy key and nonce into context-resident buffers */
	memcpy(ae_ctx->key_buf, dinit->key.data, dinit->key.length);
	ae_ctx->key_len = dinit->key.length;
	cache_operation(TEE_CACHEFLUSH, ae_ctx->key_buf, ae_ctx->key_len);

	memcpy(ae_ctx->nonce_buf, dinit->nonce.data, dinit->nonce.length);
	ae_ctx->nonce_len = dinit->nonce.length;
	cache_operation(TEE_CACHEFLUSH, ae_ctx->nonce_buf, ae_ctx->nonce_len);

	/* Set up key object */
	ae_ctx->key_obj.key_address = virt_to_phys(ae_ctx->key_buf);
	ae_ctx->key_obj.key_size = (key_len == ASU_AES_KEY_SIZE_128_BYTES) ?
				   ASU_AES_KEY_PARAM_128 :
				   ASU_AES_KEY_PARAM_256;
	ae_ctx->key_obj.key_src = ASU_AES_USER_KEY_0;
	ae_ctx->key_obj.key_id = ASU_AES_KEY_ID_0;
	cache_operation(TEE_CACHEFLUSH, &ae_ctx->key_obj,
			sizeof(ae_ctx->key_obj));

	/* Store parameters */
	ae_ctx->operation_type = dinit->encrypt ? ASU_AES_ENCRYPT_OPERATION :
					      ASU_AES_DECRYPT_OPERATION;
	ae_ctx->tag_len = dinit->tag_len;
	ae_ctx->total_aad_len = dinit->aad_len;
	ae_ctx->processed_aad_len = 0;
	ae_ctx->total_plen = dinit->payload_len;
	ae_ctx->processed_plen = 0;

	/* Send INIT request to ASUFW with total AAD/payload lengths */

	asu_authenc_set_init_params(ae_ctx, &params);
	params.aad_len = ae_ctx->total_aad_len;
	params.data_len = ae_ctx->total_plen;
	params.tag_len = ae_ctx->tag_len;
	params.operation_type = ae_ctx->operation_type;
	ae_ctx->cparam.priority = ASU_PRIORITY_HIGH;
	ae_ctx->cparam.cbhandler = NULL;

	ret = asu_aes_send(ae_ctx, &params, &fw_status);
	if (ret || fw_status) {
		EMSG("AES INIT failed: ret=%d status=0x%x",
		     ret, fw_status);
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	return ret;

cleanup:
	/* Scrub sensitive material on error */
	if (ae_ctx->key_len)
		memzero_explicit(ae_ctx->key_buf, ae_ctx->key_len);
	if (ae_ctx->nonce_len)
		memzero_explicit(ae_ctx->nonce_buf, ae_ctx->nonce_len);
	memzero_explicit(&ae_ctx->key_obj, sizeof(ae_ctx->key_obj));
	return ret;
}

/**
 * asu_authenc_update_aad() - Feed Additional Authenticated Data.
 * @dupdate: AAD update parameters
 *
 * Sends an UPDATE request carrying AAD to ASUFW.
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result
asu_authenc_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct asu_authenc_ctx *ae_ctx = dupdate->ctx;
	struct asu_aes_params params = {};
	TEE_Result ret = TEE_SUCCESS;
	uint32_t fw_status = 0;
	uint8_t *aad_dma = NULL;
	size_t remaining = 0;
	size_t offset = 0;
	size_t chunk_len = 0;

	if (!ae_ctx)
		return TEE_ERROR_BAD_STATE;

	/* Delegate to software if using fallback */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && ae_ctx->use_sw_fallback)
		return asu_authenc_sw_update_aad(ae_ctx, dupdate->aad.data,
						dupdate->aad.length);

	if (!dupdate->aad.data || !dupdate->aad.length)
		return TEE_SUCCESS;

	/* Reuse pre-allocated DMA buffer and feed AAD in chunks */
	aad_dma = ae_ctx->src_dma_buf;

	params.operation_type = ae_ctx->operation_type;
	params.mode = ae_ctx->mode;
	params.operation_flags = ASU_AES_UPDATE;

	ae_ctx->cparam.priority = ASU_PRIORITY_HIGH;
	ae_ctx->cparam.cbhandler = NULL;
	params.aad_addr = virt_to_phys(aad_dma);

	remaining = dupdate->aad.length;
	while (remaining) {
		chunk_len = MIN(remaining, (size_t)ASU_AUTHENC_DATA_CHUNK_LEN);
		memcpy(aad_dma, dupdate->aad.data + offset, chunk_len);
		cache_operation(TEE_CACHEFLUSH, aad_dma, chunk_len);

		/* Set is_last if all AAD processed and no payload follows */
		params.is_last = ASU_AES_NOT_LAST;
		if (ae_ctx->total_plen == 0 &&
		    ae_ctx->total_aad_len ==
		    (ae_ctx->processed_aad_len + chunk_len))
			params.is_last = ASU_AES_LAST;

		params.aad_len = chunk_len;

		ret = asu_aes_send(ae_ctx, &params, &fw_status);
		if (ret || fw_status) {
			EMSG("AAD update failed: ret=%d status=0x%x",
			     ret, fw_status);
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		ae_ctx->processed_aad_len += chunk_len;
		offset += chunk_len;
		remaining -= chunk_len;
	}

out:
	return ret;
}

/**
 * asu_authenc_update_payload() - Process payload data (encrypt/decrypt).
 * @dupdate: Payload update parameters
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result
asu_authenc_update_payload(struct drvcrypt_authenc_update_payload *dupdate)
{
	struct asu_authenc_ctx *ae_ctx = dupdate->ctx;
	struct asu_aes_params params = {};
	TEE_Result ret = TEE_SUCCESS;
	uint32_t fw_status = 0;
	size_t remaining = 0;
	size_t offset = 0;
	size_t chunk_len = 0;

	if (!ae_ctx)
		return TEE_ERROR_BAD_STATE;

	/* Delegate to software if using fallback */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && ae_ctx->use_sw_fallback) {
		TEE_OperationMode mode =
			ae_ctx->operation_type == ASU_AES_ENCRYPT_OPERATION ?
			TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT;

		return asu_authenc_sw_update_payload(ae_ctx, mode,
						    dupdate->src.data,
						    dupdate->src.length,
						    dupdate->dst.data);
	}

	if (!dupdate->src.data || !dupdate->src.length)
		return TEE_SUCCESS;

	if (!dupdate->dst.data || dupdate->dst.length < dupdate->src.length)
		return TEE_ERROR_BAD_PARAMETERS;

	params.operation_type = ae_ctx->operation_type;
	params.mode = ae_ctx->mode;
	params.operation_flags = ASU_AES_UPDATE;

	params.input_data_addr = virt_to_phys(ae_ctx->src_dma_buf);
	params.output_data_addr = virt_to_phys(ae_ctx->dst_dma_buf);

	ae_ctx->cparam.priority = ASU_PRIORITY_HIGH;
	ae_ctx->cparam.cbhandler = NULL;

	remaining = dupdate->src.length;
	while (remaining) {
		chunk_len = MIN(remaining, (size_t)ASU_AUTHENC_DATA_CHUNK_LEN);
		memcpy(ae_ctx->src_dma_buf,
		       dupdate->src.data + offset, chunk_len);
		cache_operation(TEE_CACHEFLUSH, ae_ctx->src_dma_buf, chunk_len);
		cache_operation(TEE_CACHEFLUSH, ae_ctx->dst_dma_buf, chunk_len);

		params.data_len = chunk_len;
		params.is_last = ((ae_ctx->processed_plen + chunk_len) ==
				  ae_ctx->total_plen) ?
				 ASU_AES_LAST : ASU_AES_NOT_LAST;

		ret = asu_aes_send(ae_ctx, &params, &fw_status);
		if (ret || fw_status) {
			EMSG("Payload update failed: ret=%d status=0x%x",
			     ret, fw_status);
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		cache_operation(TEE_CACHEINVALIDATE,
				ae_ctx->dst_dma_buf, chunk_len);
		memcpy(dupdate->dst.data + offset,
		       ae_ctx->dst_dma_buf, chunk_len);

		ae_ctx->processed_plen += chunk_len;
		offset += chunk_len;
		remaining -= chunk_len;
	}

out:
	return ret;
}

/**
 * asu_authenc_enc_final() - Finalize encryption, produce tag.
 * @dfinal: Final parameters (optional remaining payload + tag output)
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_authenc_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	struct asu_authenc_ctx *ae_ctx = dfinal->ctx;
	struct asu_aes_params params = {};
	uint8_t *tag_dma = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t fw_status = 0;
	size_t remaining = 0;
	size_t offset = 0;
	size_t chunk_len = 0;

	if (!ae_ctx)
		return TEE_ERROR_BAD_STATE;

	if (!dfinal->tag.data || dfinal->tag.length < ae_ctx->tag_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Delegate to software if using fallback */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && ae_ctx->use_sw_fallback)
		return asu_authenc_sw_enc_final(ae_ctx,
					       dfinal->src.data,
					       dfinal->src.length,
					       dfinal->dst.data,
					       dfinal->tag.data,
					       &dfinal->tag.length);

	tag_dma = memalign(ASU_DMA_ALIGN, ASU_AUTHENC_TAG_DMA_BUF_LEN);
	if (!tag_dma) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memzero_explicit(tag_dma, ASU_AUTHENC_TAG_DMA_BUF_LEN);
	cache_operation(TEE_CACHEFLUSH, tag_dma, ASU_AUTHENC_TAG_DMA_BUF_LEN);

	if (dfinal->src.length > 0) {
		if (!dfinal->src.data || !dfinal->dst.data) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
	}

	params.operation_type = ASU_AES_ENCRYPT_OPERATION;
	params.operation_flags = ASU_AES_UPDATE;
	params.mode = ae_ctx->mode;

	params.input_data_addr = virt_to_phys(ae_ctx->src_dma_buf);
	params.output_data_addr = virt_to_phys(ae_ctx->dst_dma_buf);

	ae_ctx->cparam.priority = ASU_PRIORITY_HIGH;
	ae_ctx->cparam.cbhandler = NULL;
	remaining = dfinal->src.length;
	while (remaining) {
		chunk_len = MIN(remaining, (size_t)ASU_AUTHENC_DATA_CHUNK_LEN);
		memcpy(ae_ctx->src_dma_buf,
		       dfinal->src.data + offset, chunk_len);
		cache_operation(TEE_CACHEFLUSH, ae_ctx->src_dma_buf, chunk_len);
		cache_operation(TEE_CACHEFLUSH, ae_ctx->dst_dma_buf, chunk_len);

		params.data_len = chunk_len;
		params.is_last = (remaining == chunk_len) ? ASU_AES_LAST :
				 ASU_AES_NOT_LAST;
		if (params.is_last == ASU_AES_LAST) {
			params.operation_flags |= ASU_AES_FINAL;
			params.tag_addr = virt_to_phys(tag_dma);
			params.tag_len = ae_ctx->tag_len;
		}

		ret = asu_aes_send(ae_ctx, &params, &fw_status);
		if (ret || fw_status) {
			EMSG("Enc update failed: ret=%d status=0x%x",
			     ret, fw_status);
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		cache_operation(TEE_CACHEINVALIDATE,
				ae_ctx->dst_dma_buf, chunk_len);
		memcpy(dfinal->dst.data + offset,
		       ae_ctx->dst_dma_buf, chunk_len);
		ae_ctx->processed_plen += chunk_len;
		offset += chunk_len;
		remaining -= chunk_len;
	}

	/* FINAL-only command when no payload remains in enc_final(). */
	if (dfinal->src.length == 0) {
		params.input_data_addr = 0;
		params.output_data_addr = 0;
		params.data_len = 0;
		params.operation_flags = ASU_AES_FINAL;
		params.tag_addr = virt_to_phys(tag_dma);
		params.tag_len = ae_ctx->tag_len;

		ret = asu_aes_send(ae_ctx, &params, &fw_status);
		if (ret || fw_status) {
			EMSG("Enc final failed: ret=%d status=0x%x",
			     ret, fw_status);
			ret = TEE_ERROR_GENERIC;
			goto out;
		}
	}

	/* Invalidate DMA destination before CPU reads the generated tag. */
	cache_operation(TEE_CACHEINVALIDATE, tag_dma,
			ASU_AUTHENC_TAG_DMA_BUF_LEN);
	memcpy(dfinal->tag.data, tag_dma, ae_ctx->tag_len);

out:
	free(tag_dma);
	return ret;
}

/**
 * asu_authenc_dec_final() - Finalize decryption, verify tag.
 * @dfinal: Final parameters (optional remaining payload + expected tag)
 *
 * Return: TEE_SUCCESS, TEE_ERROR_MAC_INVALID, or other error
 */
static TEE_Result asu_authenc_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	struct asu_authenc_ctx *ae_ctx = dfinal->ctx;
	struct asu_aes_params params = {};
	uint8_t *tag_dma = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t fw_status = 0;
	size_t remaining = 0;
	size_t offset = 0;
	size_t chunk_len = 0;

	if (!ae_ctx)
		return TEE_ERROR_BAD_STATE;

	if (!dfinal->tag.data || dfinal->tag.length < ae_ctx->tag_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Delegate to software if using fallback */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && ae_ctx->use_sw_fallback)
		return asu_authenc_sw_dec_final(ae_ctx,
					       dfinal->src.data,
					       dfinal->src.length,
					       dfinal->dst.data,
					       dfinal->tag.data,
					       dfinal->tag.length);

	tag_dma = memalign(ASU_DMA_ALIGN, ASU_AUTHENC_TAG_DMA_BUF_LEN);
	if (!tag_dma) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memcpy(tag_dma, dfinal->tag.data, ae_ctx->tag_len);
	cache_operation(TEE_CACHEFLUSH, tag_dma, ASU_AUTHENC_TAG_DMA_BUF_LEN);

	if (dfinal->src.length > 0) {
		if (!dfinal->src.data || !dfinal->dst.data) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
	}

	params.operation_type = ASU_AES_DECRYPT_OPERATION;
	params.operation_flags = ASU_AES_UPDATE;
	params.mode = ae_ctx->mode;

	params.input_data_addr = virt_to_phys(ae_ctx->src_dma_buf);
	params.output_data_addr = virt_to_phys(ae_ctx->dst_dma_buf);

	ae_ctx->cparam.priority = ASU_PRIORITY_HIGH;
	ae_ctx->cparam.cbhandler = NULL;

	remaining = dfinal->src.length;
	while (remaining) {
		chunk_len = MIN(remaining, (size_t)ASU_AUTHENC_DATA_CHUNK_LEN);
		memcpy(ae_ctx->src_dma_buf,
		       dfinal->src.data + offset, chunk_len);
		cache_operation(TEE_CACHEFLUSH, ae_ctx->src_dma_buf, chunk_len);
		cache_operation(TEE_CACHEFLUSH, ae_ctx->dst_dma_buf, chunk_len);

		params.data_len = chunk_len;
		params.is_last = (remaining == chunk_len) ? ASU_AES_LAST :
				 ASU_AES_NOT_LAST;
		if (params.is_last == ASU_AES_LAST) {
			params.operation_flags |= ASU_AES_FINAL;
			params.tag_addr = virt_to_phys(tag_dma);
			params.tag_len = ae_ctx->tag_len;
		}

		ret = asu_aes_send(ae_ctx, &params, &fw_status);
		if (ret || fw_status) {
			if (!ret && (fw_status & ASU_FW_STATUS_CODE_MASK) ==
					ASU_FW_AES_TAG_COMPARE_FAILED)
				ret = TEE_ERROR_MAC_INVALID;
			else
				ret = TEE_ERROR_GENERIC;
			EMSG("Dec update failed: ret=%#x status=0x%x",
			     ret, fw_status);
			goto out;
		}

		cache_operation(TEE_CACHEINVALIDATE,
				ae_ctx->dst_dma_buf, chunk_len);
		memcpy(dfinal->dst.data + offset,
		       ae_ctx->dst_dma_buf, chunk_len);
		ae_ctx->processed_plen += chunk_len;
		offset += chunk_len;
		remaining -= chunk_len;
	}

	/* FINAL-only command when no payload remains in dec_final(). */
	if (dfinal->src.length == 0) {
		params.input_data_addr = 0;
		params.output_data_addr = 0;
		params.data_len = 0;
		params.operation_flags = ASU_AES_FINAL;
		params.tag_addr = virt_to_phys(tag_dma);
		params.tag_len = ae_ctx->tag_len;

		ret = asu_aes_send(ae_ctx, &params, &fw_status);
		if (ret || fw_status) {
			if (!ret && (fw_status & ASU_FW_STATUS_CODE_MASK) ==
					ASU_FW_AES_TAG_COMPARE_FAILED)
				ret = TEE_ERROR_MAC_INVALID;
			else
				ret = TEE_ERROR_GENERIC;
			EMSG("Dec final IPI failed: ret=%#x, fw_status=0x%x",
			     ret, fw_status);
			goto out;
		}
	}

out:
	/* Scrub sensitive tag and decrypted data on failure */
	if (tag_dma)
		memzero_explicit(tag_dma, ASU_AUTHENC_TAG_DMA_BUF_LEN);
	if (ret != TEE_SUCCESS)
		memzero_explicit(dfinal->dst.data, offset);
	free(tag_dma);
	return ret;
}

/**
 * asu_authenc_final() - Clean-up after operation completes.
 * @ctx: Context
 */
static void asu_authenc_final(void *ctx)
{
	struct asu_authenc_ctx *ae_ctx = ctx;

	if (!ae_ctx)
		return;

	/* Delegate to software if using fallback */
	if (IS_ENABLED(CFG_AMD_ASU_SW_FALLBACK) && ae_ctx->use_sw_fallback) {
		asu_authenc_sw_final(ae_ctx);
		return;
	}

	/* Scrub sensitive material */
	if (ae_ctx->key_len)
		memzero_explicit(ae_ctx->key_buf, ae_ctx->key_len);
	if (ae_ctx->nonce_len)
		memzero_explicit(ae_ctx->nonce_buf, ae_ctx->nonce_len);
	memzero_explicit(&ae_ctx->key_obj, sizeof(ae_ctx->key_obj));
}

static struct drvcrypt_authenc asu_authenc_ops = {
	.alloc_ctx = asu_authenc_alloc_ctx,
	.free_ctx = asu_authenc_free_ctx,
	.init = asu_authenc_init,
	.update_aad = asu_authenc_update_aad,
	.update_payload = asu_authenc_update_payload,
	.enc_final = asu_authenc_enc_final,
	.dec_final = asu_authenc_dec_final,
	.final = asu_authenc_final,
	/*
	 * Current engine does not support partial state copy operation.
	 */
	.copy_state = NULL,
};

static TEE_Result asu_authenc_driver_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	asu_ae_dev = calloc(1, sizeof(*asu_ae_dev));
	if (!asu_ae_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	mutex_init(&asu_ae_dev->engine_lock);
	asu_ae_dev->aes_available = true;

	ret = drvcrypt_register_authenc(&asu_authenc_ops);
	if (ret)
		EMSG("ASU authenc register failed ret=%#"PRIx32, ret);

	return ret;
}

driver_init(asu_authenc_driver_init);
