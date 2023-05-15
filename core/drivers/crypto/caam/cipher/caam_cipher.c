// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Implementation of Cipher functions
 */
#include <caam_cipher.h>
#include <caam_common.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

#include "local.h"

/* Local Function declaration */
static TEE_Result do_update_streaming(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_cipher(struct drvcrypt_cipher_update *dupdate);

/*
 * Constants definition of the AES algorithm
 */
static const struct cipheralg aes_alg[] = {
	[TEE_CHAIN_MODE_ECB_NOPAD] = {
		.type = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_cipher,
	},
	[TEE_CHAIN_MODE_CBC_NOPAD] = {
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CBC),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 2 * sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_cipher,
	},
	[TEE_CHAIN_MODE_CTR] = {
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CTR_MOD128),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 2 * sizeof(uint64_t),
		.ctx_offset = 16,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_streaming,
	},
	[TEE_CHAIN_MODE_CTS] = {
		.type = 0,
	},
	[TEE_CHAIN_MODE_XTS] = {
		.type = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_KEY2 | NEED_TWEAK,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = caam_cipher_update_xts,
	},
};

/*
 * Constants definition of the DES algorithm
 */
static const struct cipheralg des_alg[] = {
	[TEE_CHAIN_MODE_ECB_NOPAD] = {
		.type = OP_ALGO(DES) | ALGO_AAI(DES_ECB),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 8, .max = 8, .mod = 8 },
		.update = do_update_cipher,
	},
	[TEE_CHAIN_MODE_CBC_NOPAD] = {
		.type = OP_ALGO(DES) | ALGO_AAI(DES_CBC),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 8, .max = 8, .mod = 8 },
		.update = do_update_cipher,
	},
};

/*
 * Constants definition of the DES3 algorithm
 */
static const struct cipheralg des3_alg[] = {
	[TEE_CHAIN_MODE_ECB_NOPAD] = {
		.type = OP_ALGO(3DES) | ALGO_AAI(DES_ECB),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 24, .mod = 8 },
		.update = do_update_cipher,
	},
	[TEE_CHAIN_MODE_CBC_NOPAD] = {
		/* Triple-DES CBC No Pad */
		.type = OP_ALGO(3DES) | ALGO_AAI(DES_CBC),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 24, .mod = 8 },
		.update = do_update_cipher,
	},
};

/*
 * Allocate context data and copy input data into
 *
 * @dst  [out] Destination data to allocate and fill
 * @src  Source of data to copy
 */
static enum caam_status copy_ctx_data(struct caambuf *dst,
				      struct drvcrypt_buf *src)
{
	enum caam_status ret = CAAM_OUT_MEMORY;

	if (!dst->data) {
		/* Allocate the destination buffer */
		ret = caam_alloc_align_buf(dst, src->length);
		if (ret != CAAM_NO_ERROR)
			return CAAM_OUT_MEMORY;
	}

	/* Do the copy */
	memcpy(dst->data, src->data, dst->length);

	/* Push data to physical memory */
	cache_operation(TEE_CACHEFLUSH, dst->data, dst->length);

	return CAAM_NO_ERROR;
}

/*
 * Verify the input key size with the requirements
 *
 * @def  Key requirements
 * @size Key size to verify
 */
static enum caam_status do_check_keysize(const struct caamdefkey *def,
					 size_t size)
{
	if (size >= def->min && size <= def->max && !(size % def->mod))
		return CAAM_NO_ERROR;

	return CAAM_BAD_PARAM;
}

enum caam_status caam_cipher_block(struct cipherdata *ctx, bool savectx,
				   uint8_t keyid, bool encrypt,
				   struct caamdmaobj *src,
				   struct caamdmaobj *dst)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = ctx->descriptor;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	if (keyid == NEED_KEY1) {
		/* Build the descriptor */
		caam_desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
						      ctx->key1.length));
		caam_desc_add_ptr(desc, ctx->key1.paddr);
	} else if (keyid == NEED_KEY2) {
		/* Build the descriptor */
		caam_desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
						      ctx->key2.length));
		caam_desc_add_ptr(desc, ctx->key2.paddr);
	}

	/* If there is a context register load it */
	if (ctx->ctx.length && ctx->alg->size_ctx) {
		caam_desc_add_word(desc, LD_NOIMM_OFF(CLASS_1, REG_CTX,
						      ctx->ctx.length,
						      ctx->alg->ctx_offset));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);
		/* Operation with the direction */
		caam_desc_add_word(desc, CIPHER_INIT(ctx->alg->type, encrypt));
	} else {
		/* Operation with the direction */
		caam_desc_add_word(desc,
				   CIPHER_INITFINAL(ctx->alg->type, encrypt));
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

	if (ctx->ctx.length && ctx->alg->size_ctx) {
		if (savectx) {
			/* Store the context */
			caam_desc_add_word(desc,
					   ST_NOIMM_OFF(CLASS_1, REG_CTX,
							ctx->ctx.length,
							ctx->alg->ctx_offset));
			caam_desc_add_ptr(desc, ctx->ctx.paddr);
		}

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
				ctx->ctx.length);
	}

	CIPHER_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("CAAM return 0x%08x Status 0x%08" PRIx32,
			     retstatus, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	return retstatus;
}

/*
 * Checks if the algorithm @algo is supported and returns the
 * local algorithm entry in the corresponding cipher array
 */
static const struct cipheralg *get_cipheralgo(uint32_t algo)
{
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_md = TEE_ALG_GET_CHAIN_MODE(algo);
	const struct cipheralg *ca = NULL;

	CIPHER_TRACE("Algo id:%" PRId32 " md:%" PRId32, algo_id, algo_md);

	switch (algo_id) {
	case TEE_MAIN_ALGO_AES:
		if (algo_md < ARRAY_SIZE(aes_alg))
			ca = &aes_alg[algo_md];
		break;

	case TEE_MAIN_ALGO_DES:
		if (algo_md < ARRAY_SIZE(des_alg))
			ca = &des_alg[algo_md];
		break;

	case TEE_MAIN_ALGO_DES3:
		if (algo_md < ARRAY_SIZE(des3_alg))
			ca = &des3_alg[algo_md];
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
static TEE_Result do_allocate(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct cipherdata *cipherdata = NULL;
	const struct cipheralg *alg = NULL;

	CIPHER_TRACE("Allocate Algo 0x%" PRIX32 " Context (%p)", algo, ctx);

	alg = get_cipheralgo(algo);
	if (!alg) {
		CIPHER_TRACE("Algorithm not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	cipherdata = caam_calloc(sizeof(*cipherdata));
	if (!cipherdata) {
		CIPHER_TRACE("Allocation Cipher data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the descriptor */
	cipherdata->descriptor = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!cipherdata->descriptor) {
		CIPHER_TRACE("Allocation descriptor error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Setup the Algorithm pointer */
	cipherdata->alg = alg;

	/* Initialize the block buffer */
	cipherdata->blockbuf.max = cipherdata->alg->size_block;

	*ctx = cipherdata;

	return TEE_SUCCESS;

out:
	caam_free_desc(&cipherdata->descriptor);
	caam_free(cipherdata);

	return ret;
}

/*
 * Free the internal cipher data context
 *
 * @ctx    Caller context variable or NULL
 */
static void do_free_intern(struct cipherdata *ctx)
{
	CIPHER_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);

		/* Free the Key 1  */
		caam_free_buf(&ctx->key1);

		/* Free the Key 2  */
		caam_free_buf(&ctx->key2);

		/* Free the Tweak */
		caam_free_buf(&ctx->tweak);

		/* Free the Context Register */
		caam_free_buf(&ctx->ctx);

		/* Free Temporary buffer */
		caam_free_buf(&ctx->blockbuf.buf);
	}
}

void caam_cipher_free(void *ctx)
{
	CIPHER_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(ctx);
	}
}

void caam_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct cipherdata *dst = dst_ctx;
	struct cipherdata *src = src_ctx;

	CIPHER_TRACE("Copy State context (%p) to (%p)", src_ctx, dst_ctx);

	dst->alg = src->alg;
	dst->encrypt = src->encrypt;

	if (src->blockbuf.filled) {
		struct caambuf srcdata = {
			.data = src->blockbuf.buf.data,
			.length = src->blockbuf.filled
		};
		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	if (src->key1.length) {
		struct drvcrypt_buf key1 = {
			.data = src->key1.data,
			.length = src->key1.length
		};
		copy_ctx_data(&dst->key1, &key1);
	}

	if (src->key2.length) {
		struct drvcrypt_buf key2 = {
			.data = src->key2.data,
			.length = src->key2.length
		};
		copy_ctx_data(&dst->key2, &key2);
	}

	if (src->ctx.length) {
		struct drvcrypt_buf ctx = {
			.data = src->ctx.data,
			.length = src->ctx.length
		};
		cache_operation(TEE_CACHEINVALIDATE, ctx.data, ctx.length);
		copy_ctx_data(&dst->ctx, &ctx);
	}

	if (src->tweak.length) {
		struct drvcrypt_buf tweak = {
			.data = src->tweak.data,
			.length = src->tweak.length
		};
		copy_ctx_data(&dst->tweak, &tweak);
	}
}

TEE_Result caam_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *cipherdata = dinit->ctx;
	const struct cipheralg *alg = NULL;

	CIPHER_TRACE("Action %s", dinit->encrypt ? "Encrypt" : "Decrypt");

	if (!cipherdata)
		return ret;

	alg = cipherdata->alg;

	/* Check if all required keys are defined */
	if (alg->require_key & NEED_KEY1) {
		if (!dinit->key1.data || !dinit->key1.length)
			goto out;

		retstatus = do_check_keysize(&alg->def_key, dinit->key1.length);
		if (retstatus != CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 1 size");
			goto out;
		}

		/* Copy the key 1 */
		retstatus = copy_ctx_data(&cipherdata->key1, &dinit->key1);
		CIPHER_TRACE("Copy Key 1 returned 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	if (alg->require_key & NEED_KEY2) {
		if (!dinit->key2.data || !dinit->key2.length)
			goto out;

		retstatus = do_check_keysize(&alg->def_key, dinit->key2.length);
		if (retstatus != CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 2 size");
			goto out;
		}

		/* Copy the key 2 */
		retstatus = copy_ctx_data(&cipherdata->key2, &dinit->key2);
		CIPHER_TRACE("Copy Key 2 returned 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	if (alg->require_key & NEED_IV) {
		if (!dinit->iv.data || !dinit->iv.length)
			goto out;

		if (dinit->iv.length != alg->size_ctx) {
			CIPHER_TRACE("Bad IV size %zu (expected %" PRId32 ")",
				     dinit->iv.length, alg->size_ctx);
			goto out;
		}

		CIPHER_TRACE("Allocate CAAM Context Register (%" PRId32
			     " bytes)",
			     alg->size_ctx);

		/* Copy the IV into the context register */
		retstatus = copy_ctx_data(&cipherdata->ctx, &dinit->iv);
		CIPHER_TRACE("Copy IV returned 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	if (alg->require_key & NEED_TWEAK) {
		/* This is accepted to start with a NULL Tweak */
		if (dinit->iv.length) {
			if (dinit->iv.length != alg->size_block) {
				CIPHER_TRACE("Bad tweak 2 size");
				goto out;
			}

			/* Copy the tweak */
			retstatus = copy_ctx_data(&cipherdata->tweak,
						  &dinit->iv);
			CIPHER_TRACE("Copy Tweak returned 0x%" PRIx32,
				     retstatus);

			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto out;
			}
		} else {
			/* Create tweak 0's */
			if (!cipherdata->tweak.data) {
				/*
				 * Allocate the destination buffer and
				 * fill it with 0's
				 */
				ret = caam_calloc_align_buf(&cipherdata->tweak,
							    alg->size_block);
				if (ret != CAAM_NO_ERROR)
					goto out;
			} else {
				/* Fill it with 0's */
				memset(cipherdata->tweak.data, 0,
				       cipherdata->tweak.length);
			}

			/* Push data to physical memory */
			cache_operation(TEE_CACHEFLUSH, cipherdata->tweak.data,
					cipherdata->tweak.length);
		}
	}

	/* Save the operation direction */
	cipherdata->encrypt = dinit->encrypt;
	cipherdata->blockbuf.filled = 0;

	ret = TEE_SUCCESS;

out:
	/* Free the internal context in case of error */
	if (ret != TEE_SUCCESS)
		do_free_intern(cipherdata);

	return ret;
}

/*
 * Update of the cipher operation in streaming mode, meaning
 * doing partial intermediate block.
 * If there is a context, the context is saved only when a
 * full block is done.
 * The partial block (if not the last block) is encrypted or
 * decrypted to return the result and it's saved to be concatened
 * to next data to rebuild a full block.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_streaming(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *ctx = dupdate->ctx;
	struct caamdmaobj src = { };
	struct caamdmaobj dst = { };
	struct caamblock trash_bck = { };
	size_t fullsize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_inmade = 0;
	size_t size_done = 0;
	size_t offset = 0;

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     ctx->encrypt ? "Encrypt" : "Decrypt");

	/* Calculate the total data to be handled */
	fullsize = ctx->blockbuf.filled + dupdate->src.length;
	CIPHER_TRACE("Fullsize %zu", fullsize);
	if (fullsize < ctx->alg->size_block) {
		size_topost = dupdate->src.length;
		goto end_streaming_post;
	} else {
		size_topost = fullsize % ctx->alg->size_block;
		/* Total size that is a cipher block multiple */
		size_todo = fullsize - size_topost;
		size_inmade = size_todo - ctx->blockbuf.filled;
	}

	CIPHER_TRACE("FullSize %zu - posted %zu - todo %zu", fullsize,
		     size_topost, size_todo);

	if (size_todo) {
		ret = caam_dmaobj_init_input(&src, dupdate->src.data,
					     dupdate->src.length);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_init_output(&dst, dupdate->dst.data,
					      dupdate->dst.length,
					      dupdate->dst.length);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_prepare(&src, &dst, ctx->alg->size_block);
		if (ret)
			goto end_streaming;
	}

	/*
	 * Check first if there is some data saved to complete the
	 * buffer.
	 */
	if (ctx->blockbuf.filled) {
		ret = caam_dmaobj_add_first_block(&src, &ctx->blockbuf);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_add_first_block(&dst, &ctx->blockbuf);
		if (ret)
			goto end_streaming;

		ctx->blockbuf.filled = 0;
	}

	size_done = size_todo;
	dupdate->dst.length = 0;
	for (offset = 0; size_todo;
	     offset += size_done, size_todo -= size_done) {
		CIPHER_TRACE("Do input %zu bytes (%zu), offset %zu", size_done,
			     size_todo, offset);

		size_done = size_todo;
		ret = caam_dmaobj_sgtbuf_inout_build(&src, &dst, &size_done,
						     offset,
						     ctx->alg->size_block);
		if (ret)
			goto end_streaming;

		retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
					      ctx->encrypt, &src, &dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_streaming;
		}

		dupdate->dst.length += caam_dmaobj_copy_to_orig(&dst);
	}

	CIPHER_DUMPBUF("Source", dupdate->src.data, dupdate->src.length);
	CIPHER_DUMPBUF("Result", dupdate->dst.data, dupdate->dst.length);

end_streaming_post:
	if (size_topost) {
		/*
		 * Save the input data in the block buffer for next operation
		 * and prepare the source DMA Object with the overall saved
		 * data to generate destination bytes.
		 */
		struct caambuf cpysrc = {
			.data = dupdate->src.data,
			.length = dupdate->src.length
		};

		caam_dmaobj_free(&src);
		caam_dmaobj_free(&dst);
		CIPHER_TRACE("Save input data %zu bytes (done %zu) - off %zu",
			     size_topost, size_inmade, offset);

		size_todo = size_topost + ctx->blockbuf.filled;

		/*
		 * Prepare the destination DMA Object:
		 *  - Use given destination parameter bytes to return
		 *  - If the previous operation saved data, use a trash
		 *    buffer to do the operation but not use unneeded data.
		 */
		ret = caam_dmaobj_init_output(&dst,
					      dupdate->dst.data + size_inmade,
					      size_topost, size_topost);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_prepare(NULL, &dst, ctx->alg->size_block);
		if (ret)
			goto end_streaming;

		if (ctx->blockbuf.filled) {
			/*
			 * Because there are some bytes to trash, use
			 * a block buffer that will be added to the
			 * destination SGT/Buffer structure to do the
			 * cipher operation.
			 */
			ret = caam_alloc_align_buf(&trash_bck.buf,
						   ctx->blockbuf.filled);
			if (ret != CAAM_NO_ERROR) {
				CIPHER_TRACE("Allocation Trash Block error");
				goto end_streaming;
			}
			trash_bck.filled = ctx->blockbuf.filled;

			ret = caam_dmaobj_add_first_block(&dst, &trash_bck);
			if (ret)
				goto end_streaming;
		}

		retstatus = caam_cpy_block_src(&ctx->blockbuf, &cpysrc,
					       size_inmade);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_streaming;
		}

		ret = caam_dmaobj_init_input(&src, ctx->blockbuf.buf.data,
					     ctx->blockbuf.filled);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_prepare(&src, NULL, ctx->alg->size_block);
		if (ret)
			goto end_streaming;

		/*
		 * Build input and output DMA Object with the same size.
		 */
		size_done = size_todo;
		ret = caam_dmaobj_sgtbuf_inout_build(&src, &dst, &size_done, 0,
						     size_todo);
		if (ret)
			goto end_streaming;

		if (size_todo != size_done) {
			CIPHER_TRACE("Invalid end streaming size %zu vs %zu",
				     size_done, size_todo);
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		retstatus = caam_cipher_block(ctx, false, NEED_KEY1,
					      ctx->encrypt, &src, &dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_streaming;
		}

		dupdate->dst.length += caam_dmaobj_copy_to_orig(&dst);

		CIPHER_DUMPBUF("Source", ctx->blockbuf.buf.data,
			       ctx->blockbuf.filled);
		CIPHER_DUMPBUF("Result", dupdate->dst.data + size_inmade,
			       size_topost);
	}

	ret = TEE_SUCCESS;

end_streaming:
	caam_dmaobj_free(&src);
	caam_dmaobj_free(&dst);

	/* Free Trash block buffer */
	caam_free_buf(&trash_bck.buf);

	return ret;
}

/*
 * Update of the cipher operation with complete block except
 * if last block. Last block can be partial block.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_cipher(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *ctx = dupdate->ctx;
	struct caamdmaobj src = { };
	struct caamdmaobj dst = { };
	size_t offset = 0;
	size_t size_todo = 0;
	size_t size_done = 0;

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     (ctx->encrypt ? "Encrypt" : "Decrypt"));

	/*
	 * Check the length of the payload/cipher to be at least
	 * one or n cipher block.
	 */
	if (dupdate->src.length < ctx->alg->size_block ||
	    dupdate->src.length % ctx->alg->size_block) {
		CIPHER_TRACE("Bad payload/cipher size %zu bytes",
			     dupdate->src.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = caam_dmaobj_init_input(&src, dupdate->src.data,
				     dupdate->src.length);
	if (ret)
		goto end_cipher;

	ret = caam_dmaobj_init_output(&dst, dupdate->dst.data,
				      dupdate->dst.length, dupdate->dst.length);
	if (ret)
		goto end_cipher;

	ret = caam_dmaobj_prepare(&src, &dst, ctx->alg->size_block);
	if (ret)
		goto end_cipher;

	size_todo = dupdate->src.length;
	dupdate->dst.length = 0;
	for (offset = 0; size_todo;
	     offset += size_done, size_todo -= size_done) {
		size_done = size_todo;
		CIPHER_TRACE("Do input %zu bytes, offset %zu", size_done,
			     offset);
		ret = caam_dmaobj_sgtbuf_inout_build(&src, &dst, &size_done,
						     offset,
						     ctx->alg->size_block);
		if (ret)
			goto end_cipher;

		retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
					      ctx->encrypt, &src, &dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto end_cipher;
		}

		dupdate->dst.length += caam_dmaobj_copy_to_orig(&dst);
	}

	ret = TEE_SUCCESS;

end_cipher:
	caam_dmaobj_free(&src);
	caam_dmaobj_free(&dst);

	return ret;
}

/*
 * Update of the cipher operation. Call the algorithm update
 * function associated.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update(struct drvcrypt_cipher_update *dupdate)
{
	struct cipherdata *cipherdata = dupdate->ctx;

	return cipherdata->alg->update(dupdate);
}

/*
 * Finalize of the cipher operation
 *
 * @ctx    Caller context variable or NULL
 */
static void do_final(void *ctx __unused)
{
}

/*
 * Registration of the Cipher Driver
 */
static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = do_allocate,
	.free_ctx = caam_cipher_free,
	.init = caam_cipher_initialize,
	.update = do_update,
	.final = do_final,
	.copy_state = caam_cipher_copy_state,
};

/*
 * Initialize the Cipher module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_cipher_init(vaddr_t ctrl_addr __unused)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (drvcrypt_register_cipher(&driver_cipher) == TEE_SUCCESS)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
