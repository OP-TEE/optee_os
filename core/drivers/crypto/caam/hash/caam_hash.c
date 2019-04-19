// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_hash.c
 *
 * @brief   CAAM Hashing manager.\n
 *          Implementation of Hashing functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_hash.h>

/* Local includes */
#include "caam_common.h"
#include "caam_hash.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"
#include "utils_status.h"

/* Hal includes */
#include "hal_ctrl.h"

/**
 * @brief   Hash Algorithm definition
 */
struct hashalg {
	uint32_t type;        ///< Algo type for operation
	uint8_t  size_digest; ///< Digest size
	uint8_t  size_block;  ///< Computing block size
	uint8_t  size_ctx;    ///< CAAM Context Register size (8 + digest size)
	uint8_t  size_key;    ///< HMAC split key size
};

#define HASH_MSG_LEN	8

/**
 * @brief   Constants definition of the Hash algorithm
 */
static const struct hashalg hash_alg[MAX_HASH_SUPPORTED] = {
	{
		/* md5 */
		.type        = OP_ALGO(MD5),
		.size_digest = TEE_MD5_HASH_SIZE,
		.size_block  = TEE_MD5_HASH_SIZE * 4,
		.size_ctx    = HASH_MSG_LEN + TEE_MD5_HASH_SIZE,
		.size_key    = 32,
	},
	{
		/* sha1 */
		.type        = OP_ALGO(SHA1),
		.size_digest = TEE_SHA1_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA1_HASH_SIZE,
		.size_key    = 40,
	},
	{
		/* sha224 */
		.type        = OP_ALGO(SHA224),
		.size_digest = TEE_SHA224_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key    = 64,
	},
	{
		/* sha256 */
		.type        = OP_ALGO(SHA256),
		.size_digest = TEE_SHA256_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key    = 64,
	},
	{
		/* sha384 */
		.type        = OP_ALGO(SHA384),
		.size_digest = TEE_SHA384_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE * 2,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key    = 128,
	},
	{
		/* sha512 */
		.type        = OP_ALGO(SHA512),
		.size_digest = TEE_SHA512_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE * 2,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key    = 128,
	},
};

/**
 * @brief    Maximum number of entry in the descriptor
 */
#define MAX_DESC_ENTRIES	20

/**
 * @brief   Local key type enumerate
 */
enum keytype {
	KEY_EMPTY = 0,  ///< No key
	KEY_PRECOMP,    ///< Precomputed key
};

/**
 * @brief   Full hashing data SW context
 */
struct hashdata {
	descPointer_t descriptor;       ///< Job descriptor

	struct caamblock blockbuf;      ///< Temporary Block buffer

	struct caambuf ctx;             ///< Hash Context used by the CAAM

	struct caambuf key;             ///< HMAC split key
	enum keytype   key_type;        ///< HMAC key type

	enum drvcrypt_hash_id algo_id;  ///< Hash Algorithm Id
	const struct hashalg  *alg;     ///< Reference to the algo constants
};

/**
 * @brief   Reduce key to be a hash algorithm block size maximum
 *
 * @param[in]  alg    Reference to the algorithm definition
 * @param[in]  inkey  Key to be reduced
 * @param[out] outkey key resulting
 *
 * @retval  CAAM_NO_ERROR      Success
 * @retval  CAAM_FAILURE       General error
 * @retval  CAAM_OUT_MEMORY    Out of memory error
 */
static enum CAAM_Status do_reduce_key(const struct hashalg *alg,
				const struct caambuf *inkey,
				struct caambuf *outkey)
{
#ifdef	CFG_CAAM_64BIT
#define KEY_REDUCE_DESC_ENTRIES	10
#else
#define KEY_REDUCE_DESC_ENTRIES	8
#endif
	enum CAAM_Status retstatus = CAAM_FAILURE;

	struct jr_jobctx jobctx  = {0};
	descPointer_t desc    = NULL;

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(KEY_REDUCE_DESC_ENTRIES);
	if (!desc) {
		retstatus = CAAM_OUT_MEMORY;
		goto exit_reduce;
	}

	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	desc_add_word(desc, HASH_INITFINAL(alg->type));

	/* Load the input key */
	desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
	desc_add_ptr(desc, inkey->paddr);
	desc_add_word(desc, inkey->length);

	/* Store key reduced */
	desc_add_word(desc, ST_NOIMM(CLASS_2, REG_CTX, outkey->length));
	desc_add_ptr(desc, outkey->paddr);
	HASH_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, inkey->data, inkey->length);
	cache_operation(TEE_CACHEFLUSH, outkey->data, outkey->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		retstatus = CAAM_FAILURE;
	} else {
		HASH_DUMPBUF("Reduced Key", outkey->data, outkey->length);
	}

exit_reduce:
	caam_free_desc(&desc);

	return retstatus;
}

/**
 * @brief   Split key of the input key using the CAAM HW HMAC operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] ikey  Input key to compute
 * @param[in] ilen  Key length
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        General error
 * @retval  TEE_ERROR_OUT_OF_MEMORY  Out of memory error
 */
static TEE_Result do_split_key(void *ctx, const uint8_t *ikey, size_t ilen)
{
#ifdef	CFG_CAAM_64BIT
#define KEY_COMPUTE_DESC_ENTRIES	10
#else
#define KEY_COMPUTE_DESC_ENTRIES	8
#endif
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct hashdata *hashdata = ctx;

	const struct hashalg *alg = hashdata->alg;

	struct caambuf inkey;
	struct caambuf key     = {0};
	struct caambuf hashkey = {0};

	struct jr_jobctx jobctx  = {0};
	descPointer_t    desc     = NULL;

	HASH_TRACE("split key length %d", ilen);

	inkey.data   = (uint8_t *)ikey;
	inkey.length = ilen;
	inkey.paddr  = virt_to_phys(inkey.data);
	if (!inkey.paddr) {
		ret = TEE_ERROR_GENERIC;
		goto exit_split_key;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(KEY_COMPUTE_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_split_key;
	}

	if (hashdata->key.data == NULL) {
		/* Allocate the split key and keep it in the context */
		retstatus = caam_alloc_align_buf(&hashdata->key, alg->size_key);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("HMAC key allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_split_key;
		}
	}

	hashdata->key.length = alg->size_key;

	if (inkey.length > alg->size_block) {
		HASH_TRACE("Input key must be reduced");

		retstatus = caam_alloc_align_buf(&hashkey, alg->size_digest);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("Reduced Key allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_split_key;
		}

		key.data   = hashkey.data;
		key.paddr  = hashkey.paddr;
		key.length = alg->size_digest;

		retstatus = do_reduce_key(alg, &inkey, &key);

		if (retstatus != CAAM_NO_ERROR)
			goto exit_split_key;
	} else {
		/* Key size is correct use directly the input key */
		key.data   = inkey.data;
		key.paddr  = inkey.paddr;
		key.length = inkey.length;
	}

	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	/* Load either input key or the reduced input key into key register */
	desc_add_word(desc, LD_KEY_PLAIN(CLASS_2, REG, key.length));
	desc_add_ptr(desc, key.paddr);
	/* Split the key */
	desc_add_word(desc, HMAC_INIT_DECRYPT(alg->type));
	desc_add_word(desc, FIFO_LD_IMM(CLASS_2, MSG, LAST_C2, 0));
	/* Store the split key */
	desc_add_word(desc, FIFO_ST(C2_MDHA_SPLIT_KEY_AES_ECB_JKEK,
					hashdata->key.length));
	desc_add_ptr(desc, hashdata->key.paddr);
	HASH_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, key.data, key.length);
	cache_operation(TEE_CACHEFLUSH, hashdata->key.data,
			hashdata->key.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		HASH_DUMPBUF("Split Key", hashdata->key.data,
			hashdata->key.length);

		hashdata->key_type = KEY_PRECOMP;
		ret = TEE_SUCCESS;
	} else {
		HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_split_key:
	caam_free_buf(&hashkey);
	caam_free_desc(&desc);

	return ret;
}

/**
 * @brief   Free the internal hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free_intern(struct hashdata *ctx)
{
	HASH_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);

		/* Free the Temporary buffer */
		caam_free_buf(&ctx->blockbuf.buf);

		/* Free the context register */
		caam_free_buf(&ctx->ctx);

		/* Free the HMAC Key */
		caam_free_buf(&ctx->key);
		ctx->key_type = KEY_EMPTY;
	}
}

/**
 * @brief   Allocate the internal hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 * @retval CAAM_NO_ERROR       Success
 * @retval CAAM_FAILURE        Generic error
 * @retval CAAM_OUT_MEMORY     Out of memory
 */
static enum CAAM_Status do_allocate_intern(struct hashdata *ctx)
{
	TEE_Result ret = CAAM_OUT_MEMORY;

	HASH_TRACE("Allocate Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	/* Allocate the descriptor */
	ctx->descriptor = caam_alloc_desc(MAX_DESC_ENTRIES);
	if (!ctx->descriptor) {
		HASH_TRACE("Allocation descriptor error");
		goto exit_alloc;
	}

	/* Initialize the block buffer */
	ctx->blockbuf.filled = 0;
	ctx->blockbuf.max    = ctx->alg->size_block;

	/* Allocate the CAAM Context register */
	ret = caam_alloc_align_buf(&ctx->ctx, ctx->alg->size_ctx);

#ifdef HASH_DEBUG
	if (ret != CAAM_NO_ERROR)
		HASH_TRACE("Allocation context register error");
#endif

	/* Ensure buffer length is 0 */
	ctx->ctx.length = 0;

exit_alloc:
	if (ret != CAAM_NO_ERROR) {
		/* Free all data allocated */
		do_free_intern(ctx);
	}

	return ret;
}

/**
 * @brief   Free the SW hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free(void *ctx)
{
	HASH_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(ctx);
	}
}

/**
 * @brief   Allocate the internal hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate(void **ctx, enum drvcrypt_hash_id algo)
{
	struct hashdata *hashdata;

	HASH_TRACE("Allocate Context (0x%"PRIxPTR") algo %d",
		(uintptr_t)ctx, algo);

	hashdata = caam_alloc(sizeof(struct hashdata));
	if (!hashdata) {
		HASH_TRACE("Allocation Hash data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	HASH_TRACE("Allocated Context (0x%"PRIxPTR")",
		(uintptr_t)hashdata);

	hashdata->algo_id = algo;
	hashdata->alg     = &hash_alg[algo];

	*ctx = hashdata;

	return TEE_SUCCESS;
}

/**
 * @brief   Initialization of the Hash operation
 *
 * @param[in] ctx   Operation Software context
 *
 * @retval TEE_SUCCESS               Success
 */
static TEE_Result do_init(void *ctx)
{
	struct hashdata *hashdata = ctx;

	HASH_TRACE("Hash Init (0x%"PRIxPTR") algo %d",
			(uintptr_t)ctx, hashdata->algo_id);

	/* Initialize the block buffer */
	hashdata->blockbuf.filled = 0;

	/* Ensure Context length is 0 */
	hashdata->ctx.length = 0;

	hashdata->key.length = 0;
	hashdata->key_type   = KEY_EMPTY;

	return TEE_SUCCESS;
}

/**
 * @brief   Update the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] data  Data to hash
 * @param[in] len   Data length
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_update(void *ctx, const uint8_t *data, size_t len)
{
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct hashdata      *hashdata = ctx;
	const struct hashalg *alg = hashdata->alg;

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;

	size_t fullSize;
	size_t size_topost;
	size_t size_todo;
	size_t size_inmade;

	size_t  inLength   = 0;
	paddr_t paddr_data = 0;

	HASH_TRACE("Hash Update (0x%"PRIxPTR") algo %d",
			(uintptr_t)ctx, hashdata->algo_id);

	if (data) {
		paddr_data = virt_to_phys((void *)data);
		if (!paddr_data) {
			HASH_TRACE("Bad input data physical address");
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto exit_update;
		}
		inLength = len;
	}

	if (!hashdata->ctx.data) {
		retstatus = do_allocate_intern(hashdata);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_update;
		}
	}

	HASH_TRACE("Update Type 0x%X - Input @0x%08"PRIxPTR"-%d",
				alg->type, (uintptr_t)data, inLength);

	/* Calculate the total data to be handled */
	fullSize = hashdata->blockbuf.filled + inLength;
	size_topost = fullSize  % alg->size_block;
	size_todo   = fullSize - size_topost;
	size_inmade = inLength - size_topost;
	HASH_TRACE("FullSize %d - posted %d - todo %d",
			fullSize, size_topost, size_todo);

	if (size_todo) {
		desc = hashdata->descriptor;
		desc_init(desc);
		desc_add_word(desc, DESC_HEADER(0));

		/* There are blocks to hash - Create the Descriptor */
		if (hashdata->ctx.length) {
			HASH_TRACE("Update Operation");
			/* Algo Operation - Update */
			desc_add_word(desc, HASH_UPDATE(alg->type));
			/* Running context to restore */
			desc_add_word(desc, LD_NOIMM(CLASS_2, REG_CTX,
					hashdata->ctx.length));
			desc_add_ptr(desc, hashdata->ctx.paddr);
		} else {
			HASH_TRACE("Init Operation");

			/* Check if there is a key to load it */
			if (hashdata->key_type == KEY_PRECOMP) {
				HASH_TRACE("Insert Key");
				desc_add_word(desc, LD_KEY_SPLIT(
					hashdata->key.length));
				desc_add_ptr(desc,
					hashdata->key.paddr);

				/* Algo Operation - HMAC Init */
				desc_add_word(desc,
					HMAC_INIT_PRECOMP(alg->type));

				/* Clean the Split key */
				cache_operation(TEE_CACHECLEAN,
					hashdata->key.data,
					hashdata->key.length);

			} else {
				/* Algo Operation - Init */
				desc_add_word(desc,
					HASH_INIT(alg->type));
			}

			hashdata->ctx.length = alg->size_ctx;
		}

		if (hashdata->blockbuf.filled != 0) {
			/* Add the temporary buffer */
			desc_add_word(desc,
				FIFO_LD_EXT(CLASS_2, MSG, NOACTION));
			desc_add_ptr(desc, hashdata->blockbuf.buf.paddr);
			desc_add_word(desc, hashdata->blockbuf.filled);

			/* Clean the circular buffer data to be loaded */
			cache_operation(TEE_CACHECLEAN,
					hashdata->blockbuf.buf.data,
					hashdata->blockbuf.filled);
			hashdata->blockbuf.filled = 0;
		}

		/* Add the input data multiple of blocksize */
		desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
		desc_add_ptr(desc, paddr_data);
		desc_add_word(desc, size_inmade);

		/* Clean the input data to be loaded */
		cache_operation(TEE_CACHECLEAN, (void *)data, size_inmade);

		/* Save the running context */
		desc_add_word(desc, ST_NOIMM(CLASS_2, REG_CTX,
					hashdata->ctx.length));
		desc_add_ptr(desc, hashdata->ctx.paddr);

		HASH_DUMPDESC(desc);

		/* Invalidate Context register */
		cache_operation(TEE_CACHEINVALIDATE, hashdata->ctx.data,
						hashdata->ctx.length);

		jobctx.desc = desc;
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			ret = TEE_SUCCESS;
			HASH_DUMPBUF("CTX", hashdata->ctx.data,
				hashdata->ctx.length);
		} else {
			HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
			ret = job_status_to_tee_result(jobctx.status);
		}
	} else {
		ret = TEE_SUCCESS;

		if (size_topost) {
			/* All input data must be saved */
			size_inmade = 0;
		}
	}

	if ((size_topost) && (data)) {
		struct drvcrypt_buf indata = {
			.data = (uint8_t *)data,
			.length = inLength};

		HASH_TRACE("Post %d of input len %d made %d",
				size_topost, len, size_inmade);
		ret = caam_cpy_block_src(&hashdata->blockbuf, &indata,
				size_inmade);
	}

exit_update:
	if (ret != TEE_SUCCESS)
		do_free_intern(hashdata);

	return ret;

}

/**
 * @brief   Finalize the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] len   Digest buffer length
 *
 * @param[out] digest  Hash digest buffer
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_final(void *ctx, uint8_t *digest, size_t len)
{
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct hashdata      *hashdata = ctx;
	const struct hashalg *alg = hashdata->alg;

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;

	int realloc = 0;
	struct caambuf digest_align = {0};

	HASH_TRACE("Hash Final (0x%"PRIxPTR") algo %d",
			(uintptr_t)ctx, hashdata->algo_id);

	if (!hashdata->ctx.data) {
		retstatus = do_allocate_intern(hashdata);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_final;
		}
	}

	if (alg->size_digest > len) {
		HASH_TRACE("Digest buffer size %d too short (%d)",
					alg->size_digest, len);

		retstatus = caam_alloc_align_buf(&digest_align,
				alg->size_digest);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("Hash digest reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_final;
		}
		realloc = 1;
	} else {
		realloc = caam_realloc_align(digest, &digest_align, len);

		if (realloc == (-1)) {
			HASH_TRACE("Hash digest reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_final;
		}
	}

	HASH_TRACE("Final Type 0x%X - Digest @0x%08"PRIxPTR"-%d",
				alg->type, (uintptr_t)digest_align.data, len);

	desc = hashdata->descriptor;
	desc_init(desc);

	/* Set the descriptor Header with length */
	desc_add_word(desc, DESC_HEADER(0));

	/* Check if there is a key to load it */
	if (hashdata->key_type == KEY_PRECOMP) {
		HASH_TRACE("Load key");

		desc_add_word(desc, LD_KEY_SPLIT(hashdata->key.length));
		desc_add_ptr(desc, hashdata->key.paddr);

		/* Clean Split key */
		cache_operation(TEE_CACHECLEAN, hashdata->key.data,
						hashdata->key.length);
	}

	if (hashdata->ctx.length) {
		HASH_TRACE("Final Operation");

		if (hashdata->key_type == KEY_PRECOMP)
			desc_add_word(desc, HMAC_FINAL_PRECOMP(alg->type));
		else
			desc_add_word(desc, HASH_FINAL(alg->type));

		/* Running context to restore */
		desc_add_word(desc, LD_NOIMM(CLASS_2, REG_CTX,
					hashdata->ctx.length));
		desc_add_ptr(desc, hashdata->ctx.paddr);

		cache_operation(TEE_CACHEINVALIDATE, hashdata->ctx.data,
						hashdata->ctx.length);
		HASH_DUMPBUF("CTX", hashdata->ctx.data, hashdata->ctx.length);
		hashdata->ctx.length = 0;
	} else {
		HASH_TRACE("Init/Final Operation");
		if (hashdata->key_type == KEY_PRECOMP)
			desc_add_word(desc, HMAC_INITFINAL_PRECOMP(alg->type));
		else
			desc_add_word(desc, HASH_INITFINAL(alg->type));
	}

	HASH_DUMPBUF("Temporary Block", hashdata->blockbuf.buf.data,
					hashdata->blockbuf.filled);
	desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
	desc_add_ptr(desc, hashdata->blockbuf.buf.paddr);
	desc_add_word(desc, hashdata->blockbuf.filled);
	cache_operation(TEE_CACHECLEAN, hashdata->blockbuf.buf.data,
					hashdata->blockbuf.filled);
	hashdata->blockbuf.filled = 0;

	/* Save the final digest */
	desc_add_word(desc, ST_NOIMM(CLASS_2, REG_CTX, alg->size_digest));
	desc_add_ptr(desc, digest_align.paddr);

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

		ret = TEE_SUCCESS;
		if (realloc)
			memcpy(digest, digest_align.data, len);

		HASH_DUMPBUF("Digest", digest_align.data, alg->size_digest);
	} else {
		HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_final:
	if (realloc == 1)
		caam_free_buf(&digest_align);

	return ret;
}

/**
 * @brief   Copy Sofware Hashing Context
 *
 * @param[in] src_ctx  Reference the context source
 *
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void do_cpy_state(void *dst_ctx, void *src_ctx)
{
	enum CAAM_Status retstatus;

	struct hashdata *dst = dst_ctx;
	struct hashdata *src = src_ctx;

	HASH_TRACE("Copy State context (0x%"PRIxPTR") to (0x%"PRIxPTR")",
			 (uintptr_t)src_ctx, (uintptr_t)dst_ctx);

	dst->algo_id = src->algo_id;
	dst->alg     = src->alg;

	if (!dst->ctx.data) {
		retstatus = do_allocate_intern(dst_ctx);
		if (retstatus != CAAM_NO_ERROR)
			return;
	}

	memcpy(dst->ctx.data, src->ctx.data, src->ctx.length);
	dst->ctx.length = src->ctx.length;
	cache_operation(TEE_CACHECLEAN, dst->ctx.data, dst->ctx.length);

	if (src->blockbuf.filled) {
		struct drvcrypt_buf srcdata = {
				.data   = src->blockbuf.buf.data,
				.length = src->blockbuf.filled};

		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	dst->key_type   = src->key_type;
	if (src->key.length) {
		if (caam_alloc_align_buf(&dst->key,
					dst->alg->size_key) == CAAM_NO_ERROR)
			memcpy(dst->key.data, src->key.data, src->key.length);
	}
}

/**
 * @brief   Registration of the HASH Driver
 */
struct drvcrypt_hash driver_hash = {
	.alloc_ctx  = &do_allocate,
	.free_ctx   = &do_free,
	.init       = &do_init,
	.update     = &do_update,
	.final      = &do_final,
	.cpy_state  = &do_cpy_state,
	.compute_key = NULL,
};

/**
 * @brief   Registration of the HMAC Driver
 */
struct drvcrypt_hash driver_hmac = {
	.alloc_ctx   = &do_allocate,
	.free_ctx    = &do_free,
	.init        = &do_init,
	.update      = &do_update,
	.final       = &do_final,
	.cpy_state   = &do_cpy_state,
	.compute_key = &do_split_key,
};


/**
 * @brief   Initialize the Hash module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_hash_init(vaddr_t ctrl_addr)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	int hash_limit;

	hash_limit = hal_ctrl_hash_limit(ctrl_addr);

	if (hash_limit > 0) {
		driver_hash.max_hash = hash_limit;
		driver_hmac.max_hash = hash_limit;

		if (drvcrypt_register(CRYPTO_HASH, &driver_hash) == 0) {
			retstatus = CAAM_NO_ERROR;

			/* Check if the HW support the HMAC Split key */
			if (hal_ctrl_splitkey(ctrl_addr)) {
				if (drvcrypt_register(CRYPTO_HMAC,
					    &driver_hmac) != 0)
					retstatus = CAAM_FAILURE;
			}
		}

	}

	return retstatus;
}
