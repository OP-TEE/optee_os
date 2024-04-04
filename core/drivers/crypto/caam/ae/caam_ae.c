// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2024 NXP
 */
#include <caam_ae.h>
#include <caam_common.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_status.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <mm/core_memprot.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <utee_types.h>

#include "local.h"

#define MAX_DESC_ENTRIES 64

/*
 * Constants definition of the AES algorithm
 */
static const struct cipheralg aes_alg[] = {
#if defined(CFG_NXP_CAAM_AE_CCM_DRV)
	[TEE_CHAIN_MODE_CCM] = {
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CCM),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 7 * sizeof(uint64_t),
		.ctx_offset = 0,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.initialize = caam_ae_initialize_ccm,
		.final = caam_ae_final_ccm,
	},
#endif
#if defined(CFG_NXP_CAAM_AE_GCM_DRV)
	[TEE_CHAIN_MODE_GCM] = {
		.type = OP_ALGO(AES) | ALGO_AAI(AES_GCM),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 8 * sizeof(uint64_t),
		.ctx_offset = 0,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.initialize = caam_ae_initialize_gcm,
		.final = caam_ae_final_gcm,
	},
#endif
};

/*
 * Checks if the algorithm @algo is supported and returns the
 * local algorithm entry in the corresponding cipher array
 */
static const struct cipheralg *get_cipheralgo(uint32_t algo)
{
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_md = TEE_ALG_GET_CHAIN_MODE(algo);
	const struct cipheralg *ca = NULL;

	AE_TRACE("Algo id:%u md:%u", algo_id, algo_md);

	switch (algo_id) {
	case TEE_MAIN_ALGO_AES:
		if (algo_md < ARRAY_SIZE(aes_alg))
			ca = &aes_alg[algo_md];
		break;

	default:
		break;
	}

	if (ca && ca->type)
		return ca;

	return NULL;
}

/*
 * Allocate the SW cipher data context
 *
 * @ctx   [out] Caller context variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result caam_ae_allocate(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct caam_ae_ctx *caam_ctx = NULL;
	const struct cipheralg *alg = NULL;

	assert(ctx);

	alg = get_cipheralgo(algo);
	if (!alg) {
		AE_TRACE("Algorithm not implemented");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	caam_ctx = caam_calloc(sizeof(*caam_ctx));
	if (!caam_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	caam_ctx->descriptor = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!caam_ctx->descriptor) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Setup the Algorithm pointer */
	caam_ctx->alg = alg;
	/* Initialize the block buffer */
	caam_ctx->blockbuf.max = caam_ctx->alg->size_block;

	*ctx = caam_ctx;

	return TEE_SUCCESS;
err:
	caam_free_desc(&caam_ctx->descriptor);
	caam_free(caam_ctx);

	return ret;
}

/*
 * Free the internal cipher data context
 *
 * @ctx    Caller context variable or NULL
 */
static void caam_ae_free(void *ctx)
{
	struct caam_ae_ctx *caam_ctx = ctx;

	assert(ctx);

	caam_free_desc(&caam_ctx->descriptor);
	caam_free_buf(&caam_ctx->key);
	caam_free_buf(&caam_ctx->nonce);
	caam_free_buf(&caam_ctx->ctx);
	caam_free_buf(&caam_ctx->initial_ctx);
	caam_free_buf(&caam_ctx->buf_aad.buf);
	caam_free_buf(&caam_ctx->blockbuf.buf);
	caam_free(caam_ctx);
}

/*
 * Initialization of the cipher operation
 *
 * @dinit  Data initialization object
 */
static TEE_Result caam_ae_initialize(struct drvcrypt_authenc_init *dinit)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_ae_ctx *caam_ctx = NULL;

	assert(dinit);

	if (dinit->aad_len >= AAD_LENGTH_OVERFLOW)
		return TEE_ERROR_NOT_SUPPORTED;

	caam_ctx = dinit->ctx;
	if (!caam_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	caam_ctx->encrypt = dinit->encrypt;
	caam_ctx->aad_length = dinit->aad_len;
	caam_ctx->payload_length = dinit->payload_len;
	caam_ctx->tag_length = dinit->tag_len;

	if (dinit->key.data && dinit->key.length) {
		retstatus = caam_cpy_buf(&caam_ctx->key, dinit->key.data,
					 dinit->key.length);
		AE_TRACE("Copy key returned %d", retstatus);
		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto err;
		}
	}

	caam_ctx->blockbuf.filled = 0;
	caam_ctx->buf_aad.filled = 0;

	ret = caam_ctx->alg->initialize(dinit);
	if (ret)
		goto err;

	return TEE_SUCCESS;
err:
	caam_free_buf(&caam_ctx->key);

	return ret;
}

/*
 * Update Additional Authenticated Data part of the authenc operation
 *
 * @dupdate  Additional Authenticated Data update object
 */
static TEE_Result
caam_ae_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_ae_ctx *caam_ctx = NULL;
	struct caambuf aad = { };

	assert(dupdate);

	caam_ctx = dupdate->ctx;
	if (!caam_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dupdate->aad.data) {
		retstatus = caam_cpy_buf(&aad, dupdate->aad.data,
					 dupdate->aad.length);
		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto out;
		}

		/* Initialize the AAD buffer if not already done */
		if (!caam_ctx->buf_aad.max)
			caam_ctx->buf_aad.max = dupdate->aad.length;

		retstatus = caam_cpy_block_src(&caam_ctx->buf_aad, &aad, 0);
		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto out;
		}
	}

	ret = TEE_SUCCESS;
out:
	caam_free_buf(&aad);
	return ret;
}

/*
 * Update of the cipher operation. Call the algorithm update
 * function associated.
 *
 * @dupdate  Data update object
 */
static TEE_Result
caam_ae_update_payload(struct drvcrypt_authenc_update_payload *dupdate)
{
	struct caam_ae_ctx *caam_ctx = NULL;

	assert(dupdate);

	caam_ctx = dupdate->ctx;
	if (!caam_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	return caam_ae_do_update(caam_ctx, &dupdate->src, &dupdate->dst, false);
}

/*
 * Last cipher update operation. Call the algorithm final
 * function associated.
 *
 * @dfinal  Data final object
 */
static TEE_Result caam_ae_final(struct drvcrypt_authenc_final *dfinal)
{
	struct caam_ae_ctx *caam_ctx = NULL;
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	assert(dfinal);

	caam_ctx = dfinal->ctx;
	if (!caam_ctx)
		return ret;

	ret = caam_ctx->alg->final(dfinal);

	caam_free_buf(&caam_ctx->nonce);
	caam_free_buf(&caam_ctx->ctx);
	caam_free_buf(&caam_ctx->initial_ctx);
	caam_free_buf(&caam_ctx->buf_aad.buf);
	caam_free_buf(&caam_ctx->blockbuf.buf);

	return ret;
}

/*
 * Finalize of the cipher operation
 *
 * @ctx    Caller context variable or NULL
 */
static void caam_ae_finalize(void *ctx __unused)
{
}

/*
 * Copy software Context
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void caam_ae_copy_state(void *dst_ctx, void *src_ctx)
{
	struct caam_ae_ctx *dst = dst_ctx;
	struct caam_ae_ctx *src = src_ctx;

	if (!dst || !src)
		return;

	AE_TRACE("Copy State context (%p) to (%p)", src_ctx, dst_ctx);

	dst->alg = src->alg;
	dst->encrypt = src->encrypt;
	dst->aad_length = src->aad_length;
	dst->tag_length = src->tag_length;
	dst->payload_length = src->payload_length;
	dst->buf_aad.max = src->buf_aad.max;
	dst->do_block = src->do_block;

	caam_free_buf(&dst->key);
	caam_free_buf(&dst->nonce);
	caam_free_buf(&dst->ctx);
	caam_free_buf(&dst->initial_ctx);
	caam_free_buf(&dst->buf_aad.buf);
	caam_free_buf(&dst->blockbuf.buf);
	dst->buf_aad.filled = 0;
	dst->blockbuf.filled = 0;

	if (src->blockbuf.filled) {
		struct caambuf srcdata = {
			.data = src->blockbuf.buf.data,
			.length = src->blockbuf.filled
		};

		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	if (src->buf_aad.filled) {
		struct caambuf srcdata = {
			.data = src->buf_aad.buf.data,
			.length = src->buf_aad.filled
		};

		caam_cpy_block_src(&dst->buf_aad, &srcdata, 0);
	}

	if (src->key.length)
		caam_cpy_buf(&dst->key, src->key.data, src->key.length);

	if (src->ctx.length)
		caam_cpy_buf(&dst->ctx, src->ctx.data, src->ctx.length);

	if (src->initial_ctx.length)
		caam_cpy_buf(&dst->initial_ctx, src->initial_ctx.data,
			     src->initial_ctx.length);

	if (src->nonce.length)
		caam_cpy_buf(&dst->nonce, src->nonce.data,
			     src->nonce.length);
}

/*
 * Registration of the Authentication Encryption Driver
 */
static struct drvcrypt_authenc driver_ae = {
	.alloc_ctx = &caam_ae_allocate,
	.free_ctx = &caam_ae_free,
	.init = &caam_ae_initialize,
	.update_aad = &caam_ae_update_aad,
	.update_payload = &caam_ae_update_payload,
	.enc_final = &caam_ae_final,
	.dec_final = &caam_ae_final,
	.final = &caam_ae_finalize,
	.copy_state = &caam_ae_copy_state,
};

/*
 * Init descriptor with a cipher key
 *
 * @caam_ctx  Reference the AE cipher context
 */
static void init_descriptor(struct caam_ae_ctx *caam_ctx)
{
	uint32_t *desc = NULL;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Build the descriptor */
	caam_desc_add_word(desc,
			   LD_KEY_PLAIN(CLASS_1, REG, caam_ctx->key.length));
	caam_desc_add_ptr(desc, caam_ctx->key.paddr);
}

/*
 * Init descriptor with an initial context
 *
 * @caam_ctx  Reference the AE cipher context
 */
static void add_initial_context(struct caam_ae_ctx *caam_ctx)
{
	uint32_t *desc = NULL;
	size_t length = 0;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;
	length = caam_ctx->initial_ctx.length;

	if (length) {
		caam_desc_add_word(desc,
				   LD_NOIMM_OFF(CLASS_1, REG_CTX, length, 0));
		caam_desc_add_ptr(desc, caam_ctx->initial_ctx.paddr);

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHECLEAN, caam_ctx->initial_ctx.data,
				length);
	}
}

/*
 * Set descriptor with a saved CAAM context
 *
 * @caam_ctx  Reference the AE cipher context
 */
static void load_context(struct caam_ae_ctx *caam_ctx)
{
	uint32_t *desc = NULL;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;

	caam_desc_add_word(desc,
			   LD_NOIMM_OFF(CLASS_1, REG_CTX, caam_ctx->ctx.length,
					caam_ctx->alg->ctx_offset));
	caam_desc_add_ptr(desc, caam_ctx->ctx.paddr);
}

/*
 * Set descriptor to saved CAAM context
 *
 * @caam_ctx  Reference the AE cipher context
 */
static void store_context(struct caam_ae_ctx *caam_ctx)
{
	uint32_t *desc = NULL;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;

	/* Store the context */
	caam_desc_add_word(desc,
			   ST_NOIMM_OFF(CLASS_1, REG_CTX, caam_ctx->ctx.length,
					caam_ctx->alg->ctx_offset));
	caam_desc_add_ptr(desc, caam_ctx->ctx.paddr);

	/* Ensure Context register data are not in cache */
	cache_operation(TEE_CACHECLEAN, caam_ctx->ctx.data,
			caam_ctx->ctx.length);
}

/*
 * Cipher operation and generates a message authentication
 *
 * @caam_ctx AE Cipher context
 * @encrypt  Encrypt or decrypt direction
 * @src      Source data to encrypt/decrypt
 * @dst      [out] Destination data encrypted/decrypted
 * @aad      Additional Authenticated data
 */
static enum caam_status caam_ae_do_oneshot(struct caam_ae_ctx *caam_ctx,
					   bool encrypt, struct caamdmaobj *src,
					   struct caamdmaobj *dst,
					   struct caamdmaobj *aad)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;

	init_descriptor(caam_ctx);

	add_initial_context(caam_ctx);

	AE_TRACE("Init/Final operation");

	/* Operation with the direction */
	caam_desc_add_word(desc,
			   CIPHER_INITFINAL(caam_ctx->alg->type, encrypt));

	if (!caam_ctx->ctx.data) {
		retstatus = caam_alloc_align_buf(&caam_ctx->ctx,
						 caam_ctx->alg->size_ctx);
		if (retstatus)
			return retstatus;
	}

	if (caam_ctx->nonce.data) {
		if (!src && !aad)
			caam_desc_add_word(desc,
					   FIFO_LD(CLASS_1, IV, LAST_C1,
						   caam_ctx->nonce.length));
		else
			caam_desc_add_word(desc,
					   FIFO_LD(CLASS_1, IV, FLUSH,
						   caam_ctx->nonce.length));
		caam_desc_add_ptr(desc, caam_ctx->nonce.paddr);

		/* Ensure Nonce data are not in cache */
		cache_operation(TEE_CACHECLEAN, caam_ctx->nonce.data,
				caam_ctx->nonce.length);
	}

	if (aad) {
		if (!src)
			caam_desc_fifo_load(desc, aad, CLASS_1, AAD, LAST_C1);
		else
			caam_desc_fifo_load(desc, aad, CLASS_1, AAD, FLUSH);
		caam_dmaobj_cache_push(aad);
	}

	/* Load the source data if any */
	if (src) {
		caam_desc_fifo_load(desc, src, CLASS_1, MSG, LAST_C1);
		caam_dmaobj_cache_push(src);
	}

	/* Store the output data if any */
	if (dst) {
		caam_desc_fifo_store(desc, dst, MSG_DATA);
		caam_dmaobj_cache_push(dst);
	}

	store_context(caam_ctx);

	AE_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);
	if (retstatus) {
		AE_TRACE("CAAM return 0x%08x Status 0x%08" PRIx32,
			 retstatus, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	/* Ensure Context register data are not in cache */
	cache_operation(TEE_CACHEINVALIDATE, caam_ctx->ctx.data,
			caam_ctx->ctx.length);

	return retstatus;
}

/*
 * Init cipher operation
 *
 * @caam_ctx AE Cipher context
 * @encrypt  Encrypt or decrypt direction
 * @aad      Additional Authenticated data
 */
static enum caam_status caam_ae_do_init(struct caam_ae_ctx *caam_ctx,
					bool encrypt, struct caamdmaobj *aad)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;

	init_descriptor(caam_ctx);

	add_initial_context(caam_ctx);

	AE_TRACE("Init operation");

	/* Operation with the direction */
	caam_desc_add_word(desc, CIPHER_INIT(caam_ctx->alg->type, encrypt));

	if (!caam_ctx->ctx.data) {
		retstatus = caam_alloc_align_buf(&caam_ctx->ctx,
						 caam_ctx->alg->size_ctx);
		if (retstatus)
			return retstatus;
	}

	if (caam_ctx->nonce.data) {
		if (!aad)
			caam_desc_add_word(desc,
					   FIFO_LD(CLASS_1, IV, LAST_C1,
						   caam_ctx->nonce.length));
		else
			caam_desc_add_word(desc,
					   FIFO_LD(CLASS_1, IV, FLUSH,
						   caam_ctx->nonce.length));
		caam_desc_add_ptr(desc, caam_ctx->nonce.paddr);

		/* Ensure Nonce data are not in cache */
		cache_operation(TEE_CACHECLEAN, caam_ctx->nonce.data,
				caam_ctx->nonce.length);
	}

	if (aad) {
		caam_desc_fifo_load(desc, aad, CLASS_1, AAD, LAST_C1);
		caam_dmaobj_cache_push(aad);
	} else if (!caam_ctx->nonce.data) {
		/* Required for null aad (initialize nonce only) */
		caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_1, AAD, LAST_C1, 0));
	}

	store_context(caam_ctx);

	AE_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);
	if (retstatus) {
		AE_TRACE("CAAM return 0x%08x Status 0x%08" PRIx32,
			 retstatus, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	/* Ensure Context register data are not in cache */
	cache_operation(TEE_CACHEINVALIDATE, caam_ctx->ctx.data,
			caam_ctx->ctx.length);

	return retstatus;
}

/*
 * Update cipher operation and generates a message authentication
 * on the last update
 *
 * @caam_ctx AE Cipher context
 * @savectx  Save or not the context
 * @encrypt  Encrypt or decrypt direction
 * @src      Source data to encrypt/decrypt
 * @dst      [out] Destination data encrypted/decrypted
 * @final    Final AES block flag
 */
static enum caam_status caam_ae_do_block(struct caam_ae_ctx *caam_ctx,
					 bool savectx, bool encrypt,
					 struct caamdmaobj *src,
					 struct caamdmaobj *dst, bool final)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;

	assert(caam_ctx);

	desc = caam_ctx->descriptor;

	if (!caam_ctx->ctx.length)
		return CAAM_NOT_INIT;

	init_descriptor(caam_ctx);

	load_context(caam_ctx);

	if (!caam_ctx->do_block ||
	    !caam_ctx->do_block(caam_ctx, encrypt, src, dst, final)) {
		if (final)
			caam_desc_add_word(desc,
					   CIPHER_FINAL(caam_ctx->alg->type,
							encrypt));
		else
			caam_desc_add_word(desc,
					   CIPHER_UPDATE(caam_ctx->alg->type,
							 encrypt));

		/* Load the source data if any */
		if (src) {
			caam_desc_fifo_load(desc, src, CLASS_1, MSG, LAST_C1);
			caam_dmaobj_cache_push(src);
		} else {
			/*
			 * Add the input data of 0 bytes to start
			 * algorithm by setting the input data size
			 */
			caam_desc_add_word(desc,
					   FIFO_LD(CLASS_1, MSG, LAST_C1, 0));
			caam_desc_add_ptr(desc, 0);
		}

		/* Store the output data if any */
		if (dst) {
			caam_desc_fifo_store(desc, dst, MSG_DATA);
			caam_dmaobj_cache_push(dst);
		}
	}

	if (savectx)
		store_context(caam_ctx);

	AE_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);
	if (retstatus) {
		AE_TRACE("CAAM return 0x%08x Status 0x%08" PRIx32,
			 retstatus, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	/* Ensure Context register data are not in cache */
	if (savectx)
		cache_operation(TEE_CACHEINVALIDATE, caam_ctx->ctx.data,
				caam_ctx->ctx.length);

	return retstatus;
}

TEE_Result caam_ae_do_update(struct caam_ae_ctx *caam_ctx,
			     struct drvcrypt_buf *src, struct drvcrypt_buf *dst,
			     bool last)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caamdmaobj caam_src = { };
	struct caamdmaobj caam_dst = { };
	struct caamdmaobj caam_aad = { };
	struct caamdmaobj *caam_aad_ptr = NULL;
	struct caamblock trash_bck = { };
	size_t full_size = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_done = 0;
	size_t size_inmade = 0;
	size_t offset = 0;
	bool do_init = false;

	if (!caam_ctx || !src || !dst)
		return TEE_ERROR_BAD_PARAMETERS;

	AE_TRACE("Length=%zu - %s", src->length,
		 caam_ctx->encrypt ? "Encrypt" : "Decrypt");

	do_init = (caam_ctx->ctx.length == 0);

	/*
	 * According to the TEE API function TEE_AEUpdateAAD
	 * Additional Authenticated data buffer could only be loaded
	 * at Init state
	 */
	if (do_init && caam_ctx->buf_aad.filled) {
		size_t aad_length = caam_ctx->buf_aad.filled;

		ret = caam_dmaobj_init_input(&caam_aad,
					     caam_ctx->buf_aad.buf.data,
					     aad_length);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_prepare(&caam_aad, NULL, aad_length);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_sgtbuf_build(&caam_aad, &aad_length, 0,
					       aad_length);
		if (ret)
			goto end_cipher;

		if (aad_length != caam_ctx->buf_aad.filled) {
			ret = TEE_ERROR_GENERIC;
			goto end_cipher;
		}

		caam_aad_ptr = &caam_aad;
	}

	/*
	 * Calculate the total data to be handled
	 * which is data saved to complete the previous buffer
	 * plus actual buffer length
	 */
	full_size = caam_ctx->blockbuf.filled + src->length;
	if (!last) {
		if (full_size < caam_ctx->alg->size_block) {
			size_topost = src->length;
			dst->length = 0;
			goto end_cipher_post;
		} else {
			size_topost = full_size % caam_ctx->alg->size_block;
			size_inmade = src->length - size_topost;
			/* Total size that is a cipher block multiple */
			size_todo = full_size - size_topost;
		}
	} else {
		/* Last total size that is the remaining data */
		size_todo = full_size;
	}

	AE_TRACE("FullSize %zu - posted %zu - todo %zu", full_size,
		 size_topost, size_todo);

	if (!size_todo) {
		if (!last) {
			ret = TEE_SUCCESS;
			goto end_cipher_post;
		} else if (do_init) {
			retstatus = caam_ae_do_oneshot(caam_ctx,
						       caam_ctx->encrypt, NULL,
						       NULL, caam_aad_ptr);

			ret = caam_status_to_tee_result(retstatus);

			/* Nothing to post on last update operation */
			goto end_cipher;
		} else {
			retstatus = caam_ae_do_block(caam_ctx, true,
						     caam_ctx->encrypt, NULL,
						     NULL, true);

			ret = caam_status_to_tee_result(retstatus);

			/* Nothing to post on last update operation */
			goto end_cipher;
		}
	}

	if (src->length) {
		ret = caam_dmaobj_init_input(&caam_src, src->data, src->length);
		if (ret)
			goto end_cipher;
	} else {
		/* Init the buffer with saved data */
		ret = caam_dmaobj_init_input(&caam_src,
					     caam_ctx->blockbuf.buf.data,
					     caam_ctx->blockbuf.filled);
		if (ret)
			goto end_cipher;

		caam_ctx->blockbuf.filled = 0;
	}

	ret = caam_dmaobj_init_output(&caam_dst, dst->data, dst->length,
				      size_todo);
	if (ret)
		goto end_cipher;

	ret = caam_dmaobj_prepare(&caam_src, &caam_dst, size_todo);
	if (ret)
		goto end_cipher;

	/* Check if there is some data saved to complete the buffer */
	if (caam_ctx->blockbuf.filled) {
		ret = caam_dmaobj_add_first_block(&caam_src,
						  &caam_ctx->blockbuf);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_add_first_block(&caam_dst,
						  &caam_ctx->blockbuf);
		if (ret)
			goto end_cipher;

		caam_ctx->blockbuf.filled = 0;
	}

	if (do_init) {
		retstatus = caam_ae_do_init(caam_ctx, caam_ctx->encrypt,
					    caam_aad_ptr);

		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_cipher;
		}
		do_init = false;
	}

	size_done = size_todo;
	dst->length = 0;
	for (offset = 0; size_todo;
	     offset += size_done, size_todo -= size_done) {
		AE_TRACE("Do input %zu bytes, offset %zu", size_done, offset);

		ret = caam_dmaobj_sgtbuf_inout_build(&caam_src, &caam_dst,
						     &size_done, offset,
						     size_todo);
		if (ret)
			goto end_cipher;

		/* is it last update and last block ? */
		if (last && size_todo == size_done)
			retstatus = caam_ae_do_block(caam_ctx, true,
						     caam_ctx->encrypt,
						     &caam_src, &caam_dst,
						     true);
		else
			retstatus = caam_ae_do_block(caam_ctx, true,
						     caam_ctx->encrypt,
						     &caam_src, &caam_dst,
						     false);

		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_cipher;
		}

		dst->length += caam_dmaobj_copy_to_orig(&caam_dst);
	}

end_cipher_post:
	if (size_topost) {
		/*
		 * Save the input data in the block buffer for next operation
		 * and prepare the source DMA Object with the overall saved
		 * data to generate destination bytes.
		 */
		struct caambuf cpysrc = { .data = src->data,
					  .length = src->length };

		caam_dmaobj_free(&caam_src);
		caam_dmaobj_free(&caam_dst);
		AE_TRACE("Save input data %zu bytes (done %zu) - off %zu",
			 size_topost, size_inmade, offset);

		size_todo = size_topost + caam_ctx->blockbuf.filled;

		/*
		 * Prepare the destination DMA Object:
		 *  - Use given destination parameter bytes to return
		 *  - If the previous operation saved data, use a trash
		 *    buffer to do the operation but don't use unneeded data.
		 */
		ret = caam_dmaobj_init_output(&caam_dst,
					      dst->data + size_inmade,
					      size_topost, size_topost);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_prepare(NULL, &caam_dst,
					  caam_ctx->alg->size_block);
		if (ret)
			goto end_cipher;

		if (caam_ctx->blockbuf.filled) {
			/*
			 * Because there are some bytes to trash, use
			 * a block buffer that will be added to the
			 * destination SGT/Buffer structure to do the
			 * cipher operation.
			 */
			ret = caam_alloc_align_buf(&trash_bck.buf,
						   caam_ctx->blockbuf.filled);
			if (ret != CAAM_NO_ERROR) {
				AE_TRACE("Allocation Trash Block error");
				goto end_cipher;
			}
			trash_bck.filled = caam_ctx->blockbuf.filled;

			ret = caam_dmaobj_add_first_block(&caam_dst,
							  &trash_bck);
			if (ret)
				goto end_cipher;
		}

		retstatus = caam_cpy_block_src(&caam_ctx->blockbuf, &cpysrc,
					       size_inmade);
		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_cipher;
		}

		ret = caam_dmaobj_init_input(&caam_src,
					     caam_ctx->blockbuf.buf.data,
					     caam_ctx->blockbuf.filled);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_prepare(&caam_src, NULL,
					  caam_ctx->alg->size_block);
		if (ret)
			goto end_cipher;

		/*
		 * Build input and output DMA Object with the same size.
		 */
		size_done = size_todo;
		ret = caam_dmaobj_sgtbuf_inout_build(&caam_src, &caam_dst,
						     &size_done, 0, size_todo);
		if (ret)
			goto end_cipher;

		if (size_todo != size_done) {
			AE_TRACE("Invalid end streaming size %zu vs %zu",
				 size_done, size_todo);
			ret = TEE_ERROR_GENERIC;
			goto end_cipher;
		}

		if (do_init) {
			retstatus = caam_ae_do_init(caam_ctx, caam_ctx->encrypt,
						    caam_aad_ptr);

			if (retstatus) {
				ret = caam_status_to_tee_result(retstatus);
				goto end_cipher;
			}
		}

		retstatus = caam_ae_do_block(caam_ctx, false, caam_ctx->encrypt,
					     &caam_src, &caam_dst, false);

		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_cipher;
		}

		dst->length += caam_dmaobj_copy_to_orig(&caam_dst);

		AE_DUMPBUF("Source", caam_ctx->blockbuf.buf.data,
			   caam_ctx->blockbuf.filled);
		AE_DUMPBUF("Result", dst->data + size_inmade, size_topost);
	}

	ret = TEE_SUCCESS;

end_cipher:
	caam_dmaobj_free(&caam_src);
	caam_dmaobj_free(&caam_dst);
	caam_dmaobj_free(&caam_aad);

	/* Free Trash block buffer */
	caam_free_buf(&trash_bck.buf);

	return ret;
}

/*
 * Initialize the authenticated encryption cipher module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_ae_init(vaddr_t ctrl_addr __unused)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (drvcrypt_register_authenc(&driver_ae) == TEE_SUCCESS)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
