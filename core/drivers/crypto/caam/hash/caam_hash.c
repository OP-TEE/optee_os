// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019, 2021 NXP
 *
 *         Implementation of Hashing functions.
 */
#include <caam_hal_ctrl.h>
#include <caam_hash.h>
#include <caam_jr.h>
#include <caam_utils_dmaobj.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <string.h>
#include <utee_defines.h>

#include "local.h"

static const struct crypto_hash_ops hash_ops;

/*
 * Maximum number of entries in the descriptor
 */
#define MAX_DESC_ENTRIES	20

/*
 * Constants definition of the hash/HMAC algorithm
 */
static const struct hashalg hash_alg[] = {
	{
		/* md5 */
		.type = OP_ALGO(MD5),
		.size_digest = TEE_MD5_HASH_SIZE,
		.size_block = TEE_MD5_HASH_SIZE * 4,
		.size_ctx = HASH_MSG_LEN + TEE_MD5_HASH_SIZE,
		.size_key = 32,
	},
	{
		/* sha1 */
		.type = OP_ALGO(SHA1),
		.size_digest = TEE_SHA1_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA1_HASH_SIZE,
		.size_key = 40,
	},
	{
		/* sha224 */
		.type = OP_ALGO(SHA224),
		.size_digest = TEE_SHA224_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key = 64,
	},
	{
		/* sha256 */
		.type = OP_ALGO(SHA256),
		.size_digest = TEE_SHA256_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key = 64,
	},
	{
		/* sha384 */
		.type = OP_ALGO(SHA384),
		.size_digest = TEE_SHA384_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE * 2,
		.size_ctx = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key = 128,
	},
	{
		/* sha512 */
		.type = OP_ALGO(SHA512),
		.size_digest = TEE_SHA512_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE * 2,
		.size_ctx = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key = 128,
	},
};

/*
 * Format the hash context to keep the reference to the
 * operation driver
 */
struct crypto_hash {
	struct crypto_hash_ctx hash_ctx; /* Crypto Hash API context */
	struct hashctx *ctx;		 /* Hash Context */
};

/*
 * Keep the HW hash limit because after the initialization
 * of the module, we don't have the CAAM Controller base address
 * to call the function returning the HW capacity.
 */
static uint8_t caam_hash_limit;

/*
 * Returns the reference to the driver context
 *
 * @ctx  API Context
 */
static struct crypto_hash *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &hash_ops);

	return container_of(ctx, struct crypto_hash, hash_ctx);
}

/*
 * Add the load key in the CAAM descriptor and clean the key buffer.
 *
 * @desc    CAAM Descriptor
 * @key     Key to load
 */
static void do_desc_load_key(uint32_t *desc, struct caambuf *key)
{
	HASH_TRACE("Insert Key");
	caam_desc_add_word(desc, LD_KEY_SPLIT(key->length));
	caam_desc_add_ptr(desc, key->paddr);

	cache_operation(TEE_CACHECLEAN, key->data, key->length);
}

/*
 * Free the internal hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_free_intern(struct hashctx *ctx)
{
	HASH_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);

		/* Free the Temporary buffer */
		caam_free_buf(&ctx->blockbuf.buf);

		/* Free the context register */
		caam_free_buf(&ctx->ctx);

		/* Free the HMAC Key */
		caam_free_buf(&ctx->key);
	}
}

/*
 * Initialization of the Hash operation
 * Call common initialization operation between hash and HMAC
 *
 * @ctx   Operation software context
 */
static TEE_Result do_hash_init(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	return caam_hash_hmac_init(hash->ctx);
}

/*
 * Update the Hash operation
 * Call common update operation between hash and HMAC
 *
 * @ctx   Operation software context
 * @data  Data to hash
 * @len   Data length
 */
static TEE_Result do_hash_update(struct crypto_hash_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	return caam_hash_hmac_update(hash->ctx, data, len);
}

/*
 * Finalize the Hash operation
 * Call common final operation between hash and HMAC
 *
 * @ctx     Operation software context
 * @digest  [out] Hash digest buffer
 * @len     Digest buffer length
 */
static TEE_Result do_hash_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
				size_t len)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	return caam_hash_hmac_final(hash->ctx, digest, len);
}

/*
 * Free the SW hashing data context
 * Call common free operation between hash and HMAC
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_hash_free(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	caam_hash_hmac_free(hash->ctx);

	free(hash);
}

/*
 * Copy Software Hashing Context
 * Call common copy operation between hash and HMAC
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void do_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
			       struct crypto_hash_ctx *src_ctx)
{
	struct crypto_hash *hash_src = to_hash_ctx(src_ctx);
	struct crypto_hash *hash_dst = to_hash_ctx(dst_ctx);

	return caam_hash_hmac_copy_state(hash_dst->ctx, hash_src->ctx);
}

/*
 * Registration of the hash Driver
 */
static const struct crypto_hash_ops hash_ops = {
	.init = do_hash_init,
	.update = do_hash_update,
	.final = do_hash_final,
	.free_ctx = do_hash_free,
	.copy_state = do_hash_copy_state,
};

/*
 * Allocate the internal hashing data context
 *
 * @ctx    [out] Caller context variable
 * @algo   Algorithm ID
 */
static TEE_Result caam_hash_allocate(struct crypto_hash_ctx **ctx,
				     uint32_t algo)
{
	struct crypto_hash *hash = NULL;
	struct hashctx *hash_ctx = NULL;
	const struct hashalg *alg = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	HASH_TRACE("Allocate Context (%p) algo %" PRId32, ctx, algo);

	*ctx = NULL;

	alg = caam_hash_get_alg(algo);
	if (!alg)
		return TEE_ERROR_NOT_IMPLEMENTED;

	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	hash_ctx = caam_calloc(sizeof(*hash_ctx));
	if (!hash_ctx) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	hash_ctx->alg = alg;
	hash->hash_ctx.ops = &hash_ops;
	hash->ctx = hash_ctx;

	*ctx = &hash->hash_ctx;

	ret = caam_hash_hmac_allocate(hash_ctx);
	if (ret != TEE_SUCCESS)
		goto err;

	HASH_TRACE("Allocated Context (%p)", hash_ctx);

	return TEE_SUCCESS;

err:
	free(hash);

	if (hash_ctx)
		caam_free(hash_ctx);

	return ret;
}

TEE_Result caam_hash_hmac_allocate(struct hashctx *ctx)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	HASH_TRACE("Allocate Context (%p)", ctx);

	/* Allocate the descriptor */
	ctx->descriptor = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!ctx->descriptor) {
		HASH_TRACE("Allocation context descriptor error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Initialize the block buffer */
	ctx->blockbuf.filled = 0;
	ctx->blockbuf.max = ctx->alg->size_block;

	/* Allocate the CAAM Context register */
	if (caam_calloc_align_buf(&ctx->ctx, ctx->alg->size_ctx) !=
	    CAAM_NO_ERROR) {
		HASH_TRACE("Allocation context register error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Allocate the Hash Key */
	if (caam_calloc_align_buf(&ctx->key, ctx->alg->size_key) !=
	    CAAM_NO_ERROR) {
		HASH_TRACE("Allocation context key error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	cache_operation(TEE_CACHEFLUSH, ctx->ctx.data, ctx->ctx.length);

	/* Ensure buffer length is 0 */
	ctx->ctx.length = 0;

	return TEE_SUCCESS;

err:
	do_free_intern(ctx);

	return ret;
}

/*
 * Free the SW hashing data context
 *
 * @ctx    Caller context variable
 */
void caam_hash_hmac_free(struct hashctx *ctx)
{
	HASH_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(ctx);
	}
}

const struct hashalg *caam_hash_get_alg(uint32_t algo)
{
	uint8_t hash_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int idx = hash_id - TEE_MAIN_ALGO_MD5;

	if (hash_id > caam_hash_limit || idx > ARRAY_SIZE(hash_alg))
		return NULL;

	return &hash_alg[idx];
}

TEE_Result caam_hash_hmac_init(struct hashctx *ctx)
{
	HASH_TRACE("Hash/HMAC Init (%p)", ctx);
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Initialize the block buffer */
	ctx->blockbuf.filled = 0;
	ctx->blockbuf.max = ctx->alg->size_block;

	/* Ensure Context length is 0 */
	ctx->ctx.length = 0;

	/* Initialize the HMAC Key */
	ctx->key.length = 0;

	ctx->initialized = true;

	return TEE_SUCCESS;
}

/*
 * Build and run the CAAM Hash descriptor to update (or start) the
 * data digest.
 *
 * @ctx    [in/out] Caller context variable
 * @src    Input data to digest
 */
static TEE_Result do_update_hash(struct hashctx *ctx, struct caamdmaobj *src)
{
	enum caam_status retstatus = CAAM_FAILURE;
	const struct hashalg *alg = ctx->alg;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = ctx->descriptor;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* There are blocks to hash - Create the Descriptor */
	if (ctx->ctx.length) {
		HASH_TRACE("Update Operation");
		/* Algo Operation - Update */
		caam_desc_add_word(desc, HASH_UPDATE(alg->type));
		/* Running context to restore */
		caam_desc_add_word(desc,
				   LD_NOIMM(CLASS_2, REG_CTX, ctx->ctx.length));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);
	} else {
		HASH_TRACE("Init Operation");

		/* Check if there is a key to load it */
		if (ctx->key.length) {
			do_desc_load_key(desc, &ctx->key);

			/* Algo Operation - HMAC Init */
			caam_desc_add_word(desc, HMAC_INIT_PRECOMP(alg->type));
		} else {
			/* Algo Operation - Init */
			caam_desc_add_word(desc, HASH_INIT(alg->type));
		}
		ctx->ctx.length = alg->size_ctx;
	}

	if (ctx->blockbuf.filled) {
		caam_desc_add_word(desc, FIFO_LD(CLASS_2, MSG, NOACTION,
						 ctx->blockbuf.filled));
		caam_desc_add_ptr(desc, ctx->blockbuf.buf.paddr);
		cache_operation(TEE_CACHECLEAN, ctx->blockbuf.buf.data,
				ctx->blockbuf.filled);
	}

	caam_desc_fifo_load(desc, src, CLASS_2, MSG, LAST_C2);
	caam_dmaobj_cache_push(src);

	ctx->blockbuf.filled = 0;

	if (ctx->ctx.length) {
		/* Save the running context */
		caam_desc_add_word(desc,
				   ST_NOIMM(CLASS_2, REG_CTX, ctx->ctx.length));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
				ctx->ctx.length);
	}

	HASH_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		HASH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		return job_status_to_tee_result(jobctx.status);
	}

	HASH_DUMPBUF("CTX", ctx->ctx.data, ctx->ctx.length);

	return TEE_SUCCESS;
}

TEE_Result caam_hash_hmac_update(struct hashctx *ctx, const uint8_t *data,
				 size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	const struct hashalg *alg = NULL;
	size_t fullsize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_done = 0;
	size_t size_inmade = 0;
	struct caamdmaobj src = { };
	size_t offset = 0;

	HASH_TRACE("Hash/HMAC Update (%p) %p - %zu", ctx, data, len);

	if ((!data && len) || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	alg = ctx->alg;

	if (!ctx->ctx.data)
		return TEE_ERROR_GENERIC;

	HASH_TRACE("Update Type 0x%" PRIX32 " - Input @%p-%zu", alg->type, data,
		   len);

	/* Calculate the total data to be handled */
	fullsize = ctx->blockbuf.filled + len;
	size_topost = fullsize % alg->size_block;
	size_todo = fullsize - size_topost;
	size_inmade = len - size_topost;
	HASH_TRACE("FullSize %zu - posted %zu - todo %zu", fullsize,
		   size_topost, size_todo);

	if (!size_todo) {
		ret = TEE_SUCCESS;

		/* All input data must be saved */
		if (size_topost)
			size_inmade = 0;

		goto save_posted;
	}

	ret = caam_dmaobj_init_input(&src, data, size_inmade);
	if (ret)
		goto exit_update;

	ret = caam_dmaobj_prepare(&src, NULL, alg->size_block);
	if (ret)
		goto exit_update;

	size_todo = size_inmade;

	for (offset = 0; offset < size_inmade;
	     offset += size_done, size_todo -= size_done) {
		size_done = size_todo;
		HASH_TRACE("Do input %zu bytes, offset %zu", size_done, offset);

		ret = caam_dmaobj_sgtbuf_build(&src, &size_done, offset,
					       alg->size_block);
		if (ret)
			goto exit_update;

		/*
		 * Need to re-adjust the length of the data if the
		 * posted data block is not empty and the SGT/Buffer
		 * is part of the full input data to do.
		 */
		if (ctx->blockbuf.filled && size_done < size_todo) {
			size_done -= ctx->blockbuf.filled;
			src.sgtbuf.length = size_done;
		}

		ret = do_update_hash(ctx, &src);
		if (ret)
			goto exit_update;
	}

save_posted:
	if (size_topost && data) {
		struct caambuf srcdata = {
			.data = (uint8_t *)data,
			.length = len,
		};

		HASH_TRACE("Posted %zu of input len %zu made %zu", size_topost,
			   len, size_inmade);

		retstatus = caam_cpy_block_src(&ctx->blockbuf, &srcdata,
					       size_inmade);
		ret = caam_status_to_tee_result(retstatus);
	}

exit_update:
	caam_dmaobj_free(&src);

	if (ret)
		do_free_intern(ctx);

	return ret;
}

TEE_Result caam_hash_hmac_final(struct hashctx *ctx, uint8_t *digest,
				size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	const struct hashalg *alg = NULL;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	struct caamdmaobj dig = { };

	HASH_TRACE("Hash/HMAC Final (%p)", ctx);

	if (!digest || !len || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	alg = ctx->alg;

	if (!ctx->ctx.data)
		return TEE_ERROR_GENERIC;

	ret = caam_dmaobj_output_sgtbuf(&dig, digest, len, alg->size_digest);
	if (ret)
		goto out;

	HASH_TRACE("Final Type 0x%" PRIX32 " - Digest %zu", alg->type, len);

	desc = ctx->descriptor;
	caam_desc_init(desc);

	/* Set the descriptor Header with length */
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Load key if any */
	if (ctx->key.length)
		do_desc_load_key(desc, &ctx->key);

	if (ctx->ctx.length) {
		HASH_TRACE("Final Operation");

		if (ctx->key.length)
			caam_desc_add_word(desc, HMAC_FINAL_PRECOMP(alg->type));
		else
			caam_desc_add_word(desc, HASH_FINAL(alg->type));

		/* Running context to restore */
		caam_desc_add_word(desc,
				   LD_NOIMM(CLASS_2, REG_CTX, ctx->ctx.length));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);

		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
				ctx->ctx.length);
		HASH_DUMPBUF("CTX", ctx->ctx.data, ctx->ctx.length);
		ctx->ctx.length = 0;
	} else {
		HASH_TRACE("Init/Final Operation");
		if (ctx->key.length)
			caam_desc_add_word(desc,
					   HMAC_INITFINAL_PRECOMP(alg->type));
		else
			caam_desc_add_word(desc, HASH_INITFINAL(alg->type));
	}

	HASH_DUMPBUF("Temporary Block", ctx->blockbuf.buf.data,
		     ctx->blockbuf.filled);

	caam_desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
	caam_desc_add_ptr(desc, ctx->blockbuf.buf.paddr);
	caam_desc_add_word(desc, ctx->blockbuf.filled);

	if (ctx->blockbuf.filled)
		cache_operation(TEE_CACHECLEAN, ctx->blockbuf.buf.data,
				ctx->blockbuf.filled);

	ctx->blockbuf.filled = 0;

	/* Save the final digest */
	caam_desc_store(desc, &dig, CLASS_2, REG_CTX);
	caam_dmaobj_cache_push(&dig);

	HASH_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		caam_dmaobj_copy_to_orig(&dig);

		HASH_DUMPBUF("Digest", digest, (size_t)alg->size_digest);

		ret = TEE_SUCCESS;
	} else {
		HASH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_dmaobj_free(&dig);

	return ret;
}

void caam_hash_hmac_copy_state(struct hashctx *dst, struct hashctx *src)
{
	HASH_TRACE("Copy State context (%p) to (%p)", src, dst);

	assert(dst && src);

	if (!dst->initialized && caam_hash_hmac_init(dst))
		panic();

	dst->alg = src->alg;

	if (src->ctx.length) {
		cache_operation(TEE_CACHEINVALIDATE, src->ctx.data,
				src->ctx.length);
		memcpy(dst->ctx.data, src->ctx.data, src->ctx.length);
		dst->ctx.length = src->ctx.length;
		cache_operation(TEE_CACHECLEAN, dst->ctx.data, dst->ctx.length);
	}

	if (src->blockbuf.filled) {
		struct caambuf srcdata = {
			.data = src->blockbuf.buf.data,
			.length = src->blockbuf.filled
		};

		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	if (src->key.data) {
		memcpy(dst->key.data, src->key.data, src->key.length);
		dst->key.length = src->key.length;
	}
}

enum caam_status caam_hash_init(struct caam_jrcfg *caam_jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t jr_base = caam_jrcfg->base + caam_jrcfg->offset;

	caam_hash_limit = caam_hal_ctrl_hash_limit(jr_base);

	if (caam_hash_limit != UINT8_MAX) {
		if (drvcrypt_register_hash(&caam_hash_allocate) == TEE_SUCCESS)
			retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}
