// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 *         Implementation of Hashing functions.
 */
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_hash.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <string.h>
#include <utee_defines.h>

static const struct crypto_hash_ops hash_ops;

/*
 * Hash Algorithm definition
 */
struct hashalg {
	uint32_t type;       /* Algo type for operation */
	uint8_t size_digest; /* Digest size */
	uint8_t size_block;  /* Computing block size */
	uint8_t size_ctx;    /* CAAM Context Register size (8 + digest size) */
};

/* First part CAAM HW Context - message length */
#define HASH_MSG_LEN	8

/*
 * Constants definition of the Hash algorithm
 */
static const struct hashalg hash_alg[] = {
	{
		/* md5 */
		.type = OP_ALGO(MD5),
		.size_digest = TEE_MD5_HASH_SIZE,
		.size_block = TEE_MD5_HASH_SIZE * 4,
		.size_ctx = HASH_MSG_LEN + TEE_MD5_HASH_SIZE,
	},
	{
		/* sha1 */
		.type = OP_ALGO(SHA1),
		.size_digest = TEE_SHA1_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA1_HASH_SIZE,
	},
	{
		/* sha224 */
		.type = OP_ALGO(SHA224),
		.size_digest = TEE_SHA224_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
	},
	{
		/* sha256 */
		.type = OP_ALGO(SHA256),
		.size_digest = TEE_SHA256_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
	},
	{
		/* sha384 */
		.type = OP_ALGO(SHA384),
		.size_digest = TEE_SHA384_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE * 2,
		.size_ctx = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
	},
	{
		/* sha512 */
		.type = OP_ALGO(SHA512),
		.size_digest = TEE_SHA512_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE * 2,
		.size_ctx = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
	},
};

/*
 * Maximum number of entry in the descriptor
 */
#define MAX_DESC_ENTRIES	20

/*
 * Full hashing data SW context
 */
struct hashdata {
	uint32_t *descriptor; /* Job descriptor */
	struct caamblock blockbuf; /* Temporary Block buffer */
	struct caambuf ctx; /* Hash Context used by the CAAM */
	const struct hashalg *alg; /* Reference to the algo constants */
};

/*
 * Format the hash context to keep the reference to the
 * operation driver
 */
struct crypto_hash {
	struct crypto_hash_ctx hash_ctx; /* Crypto Hash API context */
	struct hashdata *ctx; /* Hash Context */
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
 * Free the internal hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_free_intern(struct hashdata *ctx)
{
	HASH_TRACE("Free Context (0x%p)", ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);

		/* Free the Temporary buffer */
		caam_free_buf(&ctx->blockbuf.buf);

		/* Free the context register */
		caam_free_buf(&ctx->ctx);
	}
}

/*
 * Allocate the internal hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
static enum caam_status do_allocate_intern(struct hashdata *ctx)
{
	TEE_Result ret = CAAM_OUT_MEMORY;

	HASH_TRACE("Allocate Context (0x%p)", ctx);

	/* Allocate the descriptor */
	ctx->descriptor = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!ctx->descriptor) {
		HASH_TRACE("Allocation descriptor error");
		goto exit_alloc;
	}

	/* Initialize the block buffer */
	ctx->blockbuf.filled = 0;
	ctx->blockbuf.max = ctx->alg->size_block;

	/* Allocate the CAAM Context register */
	ret = caam_calloc_align_buf(&ctx->ctx, ctx->alg->size_ctx);

	if (ret != CAAM_NO_ERROR) {
		HASH_TRACE("Allocation context register error");
		goto exit_alloc;
	}

	cache_operation(TEE_CACHEFLUSH, ctx->ctx.data, ctx->ctx.length);

	/* Ensure buffer length is 0 */
	ctx->ctx.length = 0;

exit_alloc:
	if (ret != CAAM_NO_ERROR) {
		/* Free all data allocated */
		do_free_intern(ctx);
	}

	return ret;
}

/*
 * Free the SW hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_free(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	HASH_TRACE("Free Context (0x%p)", hash->ctx);

	if (hash->ctx) {
		do_free_intern(hash->ctx);
		caam_free(hash->ctx);
	}

	free(hash);
}

/*
 * Initialization of the Hash operation
 *
 * @ctx   Operation Software context
 */
static TEE_Result do_init(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);
	struct hashdata *hashdata = hash->ctx;

	HASH_TRACE("Hash Init (0x%p)", hashdata);
	if (!hashdata)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Initialize the block buffer */
	hashdata->blockbuf.filled = 0;

	/* Ensure Context length is 0 */
	hashdata->ctx.length = 0;

	return TEE_SUCCESS;
}

/*
 * Update the Hash operation
 *
 * @ctx   Operation Software context
 * @data  Data to hash
 * @len   Data length
 */
static TEE_Result do_update(struct crypto_hash_ctx *ctx, const uint8_t *data,
			    size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct crypto_hash *hash = to_hash_ctx(ctx);
	struct hashdata *hashdata = hash->ctx;
	const struct hashalg *alg = NULL;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	size_t fullsize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_inmade = 0;
	size_t inlen = 0;
	paddr_t paddr_data = 0;

	HASH_TRACE("Hash Update (0x%p)", hashdata);

	if ((!data && len) || !hashdata)
		return TEE_ERROR_BAD_PARAMETERS;

	alg = hashdata->alg;

	if (data) {
		paddr_data = virt_to_phys((void *)data);
		if (!paddr_data) {
			HASH_TRACE("Bad input data virtual address");
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto exit_update;
		}
		inlen = len;
	}

	if (!hashdata->ctx.data) {
		retstatus = do_allocate_intern(hashdata);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_update;
		}
	}

	HASH_TRACE("Update Type 0x%" PRIX32 " - Input @%p-%zu", alg->type,
		   data, inlen);

	/* Calculate the total data to be handled */
	fullsize = hashdata->blockbuf.filled + inlen;
	size_topost = fullsize % alg->size_block;
	size_todo = fullsize - size_topost;
	size_inmade = inlen - size_topost;
	HASH_TRACE("FullSize %zu - posted %zu - todo %zu", fullsize,
		   size_topost, size_todo);

	if (size_todo) {
		desc = hashdata->descriptor;
		caam_desc_init(desc);
		caam_desc_add_word(desc, DESC_HEADER(0));

		/* There are blocks to hash - Create the Descriptor */
		if (hashdata->ctx.length) {
			HASH_TRACE("Update Operation");
			/* Algo Operation - Update */
			caam_desc_add_word(desc, HASH_UPDATE(alg->type));
			/* Running context to restore */
			caam_desc_add_word(desc,
					   LD_NOIMM(CLASS_2, REG_CTX,
						    hashdata->ctx.length));
			caam_desc_add_ptr(desc, hashdata->ctx.paddr);
		} else {
			HASH_TRACE("Init Operation");

			/* Algo Operation - Init */
			caam_desc_add_word(desc, HASH_INIT(alg->type));

			hashdata->ctx.length = alg->size_ctx;
		}

		if (hashdata->blockbuf.filled != 0) {
			/* Add the temporary buffer */
			caam_desc_add_word(desc,
					   FIFO_LD_EXT(CLASS_2, MSG, NOACTION));
			caam_desc_add_ptr(desc, hashdata->blockbuf.buf.paddr);
			caam_desc_add_word(desc, hashdata->blockbuf.filled);

			/* Clean the circular buffer data to be loaded */
			cache_operation(TEE_CACHECLEAN,
					hashdata->blockbuf.buf.data,
					hashdata->blockbuf.filled);
			hashdata->blockbuf.filled = 0;
		}

		/* Add the input data multiple of blocksize */
		caam_desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
		caam_desc_add_ptr(desc, paddr_data);
		caam_desc_add_word(desc, size_inmade);

		/* Clean the input data to be loaded */
		cache_operation(TEE_CACHECLEAN, (void *)data, size_inmade);

		/* Save the running context */
		caam_desc_add_word(desc, ST_NOIMM(CLASS_2, REG_CTX,
						  hashdata->ctx.length));
		caam_desc_add_ptr(desc, hashdata->ctx.paddr);

		HASH_DUMPDESC(desc);

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, hashdata->ctx.data,
				hashdata->ctx.length);

		jobctx.desc = desc;
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			ret = TEE_SUCCESS;
			HASH_DUMPBUF("CTX", hashdata->ctx.data,
				     hashdata->ctx.length);
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
		struct caambuf indata = {
			.data = (uint8_t *)data,
			.length = inlen
		};

		HASH_TRACE("Post %zu of input len %zu made %zu", size_topost,
			   len, size_inmade);
		ret = caam_cpy_block_src(&hashdata->blockbuf, &indata,
					 size_inmade);
	}

exit_update:
	if (ret != TEE_SUCCESS)
		do_free_intern(hashdata);

	return ret;
}

/*
 * Finalize the Hash operation
 *
 * @ctx     Operation Software context
 * @digest  [out] Hash digest buffer
 * @len     Digest buffer length
 */
static TEE_Result do_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
			   size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct crypto_hash *hash = to_hash_ctx(ctx);
	struct hashdata *hashdata = hash->ctx;
	const struct hashalg *alg = NULL;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	int realloc = 0;
	struct caambuf digest_align = {};

	HASH_TRACE("Hash Final (0x%p)", hashdata);

	if (!digest || !len || !hashdata)
		return TEE_ERROR_BAD_PARAMETERS;

	alg = hashdata->alg;

	if (!hashdata->ctx.data) {
		retstatus = do_allocate_intern(hashdata);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_final;
		}
	}

	if (alg->size_digest > len) {
		HASH_TRACE("Digest buffer size %" PRId8 " too short (%zu)",
			   alg->size_digest, len);

		retstatus =
			caam_alloc_align_buf(&digest_align, alg->size_digest);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("Hash digest reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_final;
		}
		realloc = 1;
	} else {
		realloc =
			caam_set_or_alloc_align_buf(digest, &digest_align, len);

		if (realloc == -1) {
			HASH_TRACE("Hash digest reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_final;
		}
	}

	HASH_TRACE("Final Type 0x%" PRIX32 " - Digest @%p-%zu", alg->type,
		   digest_align.data, len);

	desc = hashdata->descriptor;
	caam_desc_init(desc);

	/* Set the descriptor Header with length */
	caam_desc_add_word(desc, DESC_HEADER(0));

	if (hashdata->ctx.length) {
		HASH_TRACE("Final Operation");

		caam_desc_add_word(desc, HASH_FINAL(alg->type));

		/* Running context to restore */
		caam_desc_add_word(desc, LD_NOIMM(CLASS_2, REG_CTX,
						  hashdata->ctx.length));
		caam_desc_add_ptr(desc, hashdata->ctx.paddr);

		cache_operation(TEE_CACHEINVALIDATE, hashdata->ctx.data,
				hashdata->ctx.length);
		HASH_DUMPBUF("CTX", hashdata->ctx.data, hashdata->ctx.length);
		hashdata->ctx.length = 0;
	} else {
		HASH_TRACE("Init/Final Operation");
		caam_desc_add_word(desc, HASH_INITFINAL(alg->type));
	}

	HASH_DUMPBUF("Temporary Block", hashdata->blockbuf.buf.data,
		     hashdata->blockbuf.filled);
	caam_desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
	caam_desc_add_ptr(desc, hashdata->blockbuf.buf.paddr);
	caam_desc_add_word(desc, hashdata->blockbuf.filled);
	cache_operation(TEE_CACHECLEAN, hashdata->blockbuf.buf.data,
			hashdata->blockbuf.filled);
	hashdata->blockbuf.filled = 0;

	/* Save the final digest */
	caam_desc_add_word(desc, ST_NOIMM(CLASS_2, REG_CTX, alg->size_digest));
	caam_desc_add_ptr(desc, digest_align.paddr);

	HASH_DUMPDESC(desc);

	jobctx.desc = desc;

	if (digest_align.nocache == 0)
		cache_operation(TEE_CACHEFLUSH, digest_align.data,
				alg->size_digest);

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

exit_final:
	if (realloc == 1)
		caam_free_buf(&digest_align);

	return ret;
}

/*
 * Copy Sofware Hashing Context
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void do_copy_state(struct crypto_hash_ctx *dst_ctx,
			  struct crypto_hash_ctx *src_ctx)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct crypto_hash *hash_src = to_hash_ctx(src_ctx);
	struct crypto_hash *hash_dst = to_hash_ctx(dst_ctx);
	struct hashdata *dst = hash_dst->ctx;
	struct hashdata *src = hash_src->ctx;

	HASH_TRACE("Copy State context (0x%p) to (0x%p)", src, dst);

	if (!dst || !src)
		panic();

	dst->alg = src->alg;

	if (!dst->ctx.data) {
		retstatus = do_allocate_intern(dst);
		if (retstatus != CAAM_NO_ERROR)
			panic();
	}

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
}

/*
 * Registration of the hash Driver
 */
static const struct crypto_hash_ops hash_ops = {
	.init = do_init,
	.update = do_update,
	.final = do_final,
	.free_ctx = do_free,
	.copy_state = do_copy_state,
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
	struct hashdata *hashdata = NULL;
	uint8_t hash_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_idx = hash_id - TEE_MAIN_ALGO_MD5;

	HASH_TRACE("Allocate Context (%p) algo %" PRId16, ctx, algo_idx);

	*ctx = NULL;

	if (hash_id > caam_hash_limit)
		return TEE_ERROR_NOT_IMPLEMENTED;

	if (algo_idx > ARRAY_SIZE(hash_alg))
		return TEE_ERROR_NOT_IMPLEMENTED;

	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	hashdata = caam_calloc(sizeof(*hashdata));
	if (!hashdata) {
		HASH_TRACE("Allocation Hash data error");
		free(hash);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	HASH_TRACE("Allocated Context (0x%p)", hashdata);

	hashdata->alg = &hash_alg[algo_idx];

	hash->hash_ctx.ops = &hash_ops;
	hash->ctx = hashdata;

	*ctx = &hash->hash_ctx;

	return TEE_SUCCESS;
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
