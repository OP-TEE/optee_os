// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 *         Implementation of Hashing functions.
 */
#include <caam_hal_ctrl.h>
#include <caam_hash.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
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

	ctx->blockbuf.filled = 0;

	/* Ensure Context length is 0 */
	ctx->ctx.length = 0;

	/* Initialize the HMAC Key */
	ctx->key.length = 0;

	return TEE_SUCCESS;
}

TEE_Result caam_hash_hmac_update(struct hashctx *ctx, const uint8_t *data,
				 size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	const struct hashalg *alg = NULL;
	uint32_t alg_type = 0;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	size_t fullsize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_inmade = 0;
	struct caamsgtbuf src_sgt = { .sgt_type = false };
	struct caambuf indata = { .data = (uint8_t *)data, .length = len };

	HASH_TRACE("Hash/HMAC Update (%p) %p - %zu", ctx, data, len);

	if ((!data && len) || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	alg = ctx->alg;
	alg_type = alg->type;

	if (data) {
		indata.paddr = virt_to_phys((void *)data);
		if (!indata.paddr) {
			HASH_TRACE("Bad input data virtual address");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		if (!caam_mem_is_cached_buf(indata.data, indata.length))
			indata.nocache = 1;
	}

	if (!ctx->ctx.data)
		return TEE_ERROR_GENERIC;

	HASH_TRACE("Update Type 0x%" PRIX32 " - Input @%p-%zu", alg_type,
		   indata.data, indata.length);

	/* Calculate the total data to be handled */
	fullsize = ctx->blockbuf.filled + indata.length;
	size_topost = fullsize % alg->size_block;
	size_todo = fullsize - size_topost;
	size_inmade = indata.length - size_topost;
	HASH_TRACE("FullSize %zu - posted %zu - todo %zu", fullsize,
		   size_topost, size_todo);

	if (size_todo) {
		desc = ctx->descriptor;
		caam_desc_init(desc);
		caam_desc_add_word(desc, DESC_HEADER(0));

		/* There are blocks to hash - Create the Descriptor */
		if (ctx->ctx.length) {
			HASH_TRACE("Update Operation");
			/* Algo Operation - Update */
			caam_desc_add_word(desc, HASH_UPDATE(alg_type));
			/* Running context to restore */
			caam_desc_add_word(desc, LD_NOIMM(CLASS_2, REG_CTX,
							  ctx->ctx.length));
			caam_desc_add_ptr(desc, ctx->ctx.paddr);
		} else {
			HASH_TRACE("Init Operation");

			/* Check if there is a key to load it */
			if (ctx->key.length) {
				do_desc_load_key(desc, &ctx->key);

				/* Algo Operation - HMAC Init */
				caam_desc_add_word(desc,
						   HMAC_INIT_PRECOMP(alg_type));
			} else {
				/* Algo Operation - Init */
				caam_desc_add_word(desc, HASH_INIT(alg_type));
			}
			ctx->ctx.length = alg->size_ctx;
		}

		/* Set the exact size of input data to use */
		indata.length = size_inmade;

		if (ctx->blockbuf.filled)
			retstatus = caam_sgt_build_block_data(&src_sgt,
							      &ctx->blockbuf,
							      &indata);
		else
			retstatus = caam_sgt_build_block_data(&src_sgt, NULL,
							      &indata);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		if (src_sgt.sgt_type) {
			if (src_sgt.length > FIFO_LOAD_MAX) {
				caam_desc_add_word(desc,
						   FIFO_LD_SGT_EXT(CLASS_2, MSG,
								   LAST_C2));
				caam_desc_add_ptr(desc,
						  virt_to_phys(src_sgt.sgt));
				caam_desc_add_word(desc, src_sgt.length);
			} else {
				caam_desc_add_word(desc,
						   FIFO_LD_SGT(CLASS_2, MSG,
							       LAST_C2,
							       src_sgt.length));
				caam_desc_add_ptr(desc,
						  virt_to_phys(src_sgt.sgt));
			}
			caam_sgt_cache_op(TEE_CACHECLEAN, &src_sgt);
		} else {
			if (src_sgt.length > FIFO_LOAD_MAX) {
				caam_desc_add_word(desc,
						   FIFO_LD_EXT(CLASS_2, MSG,
							       LAST_C2));
				caam_desc_add_ptr(desc, src_sgt.buf->paddr);
				caam_desc_add_word(desc, src_sgt.length);
			} else {
				caam_desc_add_word(desc,
						   FIFO_LD(CLASS_2, MSG,
							   LAST_C2,
							   src_sgt.length));
				caam_desc_add_ptr(desc, src_sgt.buf->paddr);
			}

			if (!src_sgt.buf->nocache)
				cache_operation(TEE_CACHECLEAN,
						src_sgt.buf->data,
						src_sgt.length);
		}

		ctx->blockbuf.filled = 0;

		/* Save the running context */
		caam_desc_add_word(desc,
				   ST_NOIMM(CLASS_2, REG_CTX, ctx->ctx.length));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);

		HASH_DUMPDESC(desc);

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
				ctx->ctx.length);

		jobctx.desc = desc;
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			ret = TEE_SUCCESS;
			HASH_DUMPBUF("CTX", ctx->ctx.data, ctx->ctx.length);
		} else {
			HASH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
			ret = job_status_to_tee_result(jobctx.status);
		}
	} else {
		ret = TEE_SUCCESS;

		if (size_topost) {
			/* All input data must be saved */
			size_inmade = 0;
		}
	}

	if (size_topost && data) {
		/*
		 * Set the full data size of the input buffer.
		 * indata.length has been changed when creating the SGT
		 * object.
		 */
		indata.length = len;
		HASH_TRACE("Posted %zu of input len %zu made %zu", size_topost,
			   indata.length, size_inmade);
		ret = caam_cpy_block_src(&ctx->blockbuf, &indata, size_inmade);
	}

out:
	if (src_sgt.sgt_type)
		caam_sgtbuf_free(&src_sgt);

	if (ret != TEE_SUCCESS)
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
	int realloc = 0;
	struct caambuf digest_align = { };
	struct caamsgtbuf sgtdigest = { .sgt_type = false };

	HASH_TRACE("Hash/HMAC Final (%p)", ctx);

	if (!digest || !len || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	alg = ctx->alg;

	if (!ctx->ctx.data)
		return TEE_ERROR_GENERIC;

	if (alg->size_digest > len) {
		HASH_TRACE("Digest buffer size %" PRId8 " too short (%zu)",
			   alg->size_digest, len);

		retstatus =
			caam_alloc_align_buf(&digest_align, alg->size_digest);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("Digest reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		realloc = 1;
	} else {
		realloc =
			caam_set_or_alloc_align_buf(digest, &digest_align, len);

		if (realloc == -1) {
			HASH_TRACE("Digest reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		retstatus = caam_sgt_build_block_data(&sgtdigest, NULL,
						      &digest_align);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	HASH_TRACE("Final Type 0x%" PRIX32 " - Digest @%p-%zu", alg->type,
		   digest_align.data, len);

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

	cache_operation(TEE_CACHECLEAN, ctx->blockbuf.buf.data,
			ctx->blockbuf.filled);

	ctx->blockbuf.filled = 0;

	/* Save the final digest */
	if (sgtdigest.sgt_type) {
		caam_desc_add_word(desc, ST_SGT_NOIMM(CLASS_2, REG_CTX,
						      alg->size_digest));
		caam_desc_add_ptr(desc, virt_to_phys(sgtdigest.sgt));

		caam_sgt_cache_op(TEE_CACHEFLUSH, &sgtdigest);
	} else {
		caam_desc_add_word(desc, ST_NOIMM(CLASS_2, REG_CTX,
						  alg->size_digest));
		caam_desc_add_ptr(desc, digest_align.paddr);

		if (digest_align.nocache == 0)
			cache_operation(TEE_CACHEFLUSH, digest_align.data,
					alg->size_digest);
	}

	HASH_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		/* Ensure that hash data are correct in cache */
		if (digest_align.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, digest_align.data,
					alg->size_digest);

		if (realloc)
			memcpy(digest, digest_align.data, len);

		HASH_DUMPBUF("Digest", digest_align.data,
			     (size_t)alg->size_digest);

		ret = TEE_SUCCESS;
	} else {
		HASH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	if (realloc == 1)
		caam_free_buf(&digest_align);

	if (sgtdigest.sgt_type)
		caam_sgtbuf_free(&sgtdigest);

	return ret;
}

void caam_hash_hmac_copy_state(struct hashctx *dst, struct hashctx *src)
{
	HASH_TRACE("Copy State context (%p) to (%p)", src, dst);

	assert(dst && src);

	dst->alg = src->alg;

	memcpy(dst->ctx.data, src->ctx.data, src->ctx.length);
	dst->ctx.length = src->ctx.length;
	cache_operation(TEE_CACHECLEAN, dst->ctx.data, dst->ctx.length);

	if (src->blockbuf.filled) {
		struct caambuf srcdata = {
			.data = src->blockbuf.buf.data,
			.length = src->blockbuf.filled
		};

		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	if (src->key.data)
		memcpy(dst->key.data, src->key.data, src->key.length);
}

enum caam_status caam_hash_init(vaddr_t ctrl_addr)
{
	enum caam_status retstatus = CAAM_FAILURE;

	caam_hash_limit = caam_hal_ctrl_hash_limit(ctrl_addr);

	if (caam_hash_limit != UINT8_MAX) {
		if (drvcrypt_register_hash(&caam_hash_allocate) == TEE_SUCCESS)
			retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}
