// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_cipher.c
 *
 * @brief   CAAM Cipher manager.\n
 *          Implementation of Cipher functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <assert.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>
#include <util.h>

/* Local includes */
#include "caam_cipher.h"
#include "caam_common.h"
#include "caam_jr.h"
#include "local.h"

/* Utils includes */
#include "utils_mem.h"
#include "utils_sgt.h"

/**
 * @brief   Max Cipher Buffer to encrypt/decrypt at each operation
 */
#define MAX_CIPHER_BUFFER	(8 * 1024)

/* Local Function declaration */
static TEE_Result do_update_streaming(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_cipher(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_mac(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_cts(struct drvcrypt_cipher_update *dupdate);

/**
 * @brief   Constants definition of the AES algorithm
 */
static const struct cipheralg aes_alg[MAX_AES_SUPPORTED] = {
	{
		/* AES ECB No Pad */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 0,
		.ctx_offset  = 0,
		.require_key = NEED_KEY1,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_cipher,
	},
	{
		/* AES CBC No Pad */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_CBC),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_cipher,
	},
	{
		/* AES CTR */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_CTR_MOD128),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 16,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_streaming,
	},
	{
		/* AES CTS, combinaison of CBC and ECB mode */
		.type        = 0,
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_cts,
	},
	{
		/* AES XTS, tweakable ECB cipher block */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 0,
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_KEY2 | NEED_TWEAK,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_xts,
	},
	{
		/* AES CBC MAC */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_CBC),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_mac,
	},
};

/**
 * @brief   Constants definition of the DES algorithm
 */
static const struct cipheralg des_alg[MAX_DES_SUPPORTED] = {
	{
		/* DES ECB No Pad */
		.type        = OP_ALGO(DES) | ALGO_AAI(DES_ECB),
		.size_block  = TEE_DES_BLOCK_SIZE,
		.size_ctx    = 0,
		.ctx_offset  = 0,
		.require_key = NEED_KEY1,
		.def_key     = {.min = 8, .max = 8, .mod = 8},
		.update      = do_update_cipher,
	},
	{
		/* DES CBC No Pad */
		.type        = OP_ALGO(DES) | ALGO_AAI(DES_CBC),
		.size_block  = TEE_DES_BLOCK_SIZE,
		.size_ctx    = sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 8, .max = 8, .mod = 8},
		.update      = do_update_cipher,
	},
	{
		/* DES CBC MAC */
		.type        = OP_ALGO(DES) | ALGO_AAI(DES_CBC),
		.size_block  = TEE_DES_BLOCK_SIZE,
		.size_ctx    = sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 8, .max = 8, .mod = 8},
		.update      = do_update_mac,
	},
};

/**
 * @brief   Constants definition of the DES3 algorithm
 */
static const struct cipheralg des3_alg[MAX_DES3_SUPPORTED] = {
	{
		/* Triple-DES ECB No Pad */
		.type        = OP_ALGO(3DES) | ALGO_AAI(DES_ECB),
		.size_block  = TEE_DES_BLOCK_SIZE,
		.size_ctx    = 0,
		.ctx_offset  = 0,
		.require_key = NEED_KEY1,
		.def_key     = {.min = 16, .max = 24, .mod = 8},
		.update      = do_update_cipher,
	},
	{
		/* Triple-DES CBC No Pad */
		.type        = OP_ALGO(3DES) | ALGO_AAI(DES_CBC),
		.size_block  = TEE_DES_BLOCK_SIZE,
		.size_ctx    = sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 24, .mod = 8},
		.update      = do_update_cipher,
	},
	{
		/* Triple-DES CBC MAC */
		.type        = OP_ALGO(3DES) | ALGO_AAI(DES_CBC),
		.size_block  = TEE_DES_BLOCK_SIZE,
		.size_ctx    = sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 24, .mod = 8},
		.update      = do_update_mac,
	},
};

/**
 * @brief   Allocate context data and copy input data into
 *
 * @param[in]  src  Source of data to copy
 * @param[out] dst  Destination data to allocate and fill
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_OUT_MEMORY Allocation error
 */
static enum CAAM_Status copy_ctx_data(struct caambuf *dst,
			struct drvcrypt_buf *src)
{
	enum CAAM_Status ret;

	if (!dst->data) {
		/* Allocate the destination buffer */
		ret = caam_alloc_align_buf(dst, src->length);
		if (ret != CAAM_NO_ERROR)
			return ret;
	}

	/* Do the copy */
	memcpy(dst->data, src->data, dst->length);

	/* Push data to physical memory */
	cache_operation(TEE_CACHEFLUSH, dst->data, dst->length);

	return CAAM_NO_ERROR;
}

/**
 * @brief  Verifies the input key size with the requirements
 *
 * @param[in] def  Key requirements
 * @param[in] size Key size to verify
 *
 * @retval CAAM_NO_ERROR   Success
 * @retval CAAM_BAD_PARAM  Bad parameters
 */
static enum CAAM_Status do_check_keysize(const struct defkey *def, size_t size)
{
	if ((size >= def->min) && (size <= def->max)) {
		if ((size % def->mod) == 0)
			return CAAM_NO_ERROR;
	}

	return CAAM_BAD_PARAM;
}

/**
 * @brief   Update of the cipher operation of complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in]  ctx      Cipher context
 * @param[in]  savectx  Save or not the context
 * @param[in]  keyid    Id of the key to be used during operation
 * @param[in]  encrypt  Encrypt or decrypt direction
 * @param[in]  src      Source data to encrypt/decrypt
 * @param[out] dst      Destination data encrypted/decrypted
 *
 * @retval CAAM_NO_ERROR  Success
 * @retval CAAM_FAILURE   Other Error
 */
enum CAAM_Status do_block(struct cipherdata *ctx,
				bool savectx, uint8_t keyid, bool encrypt,
				struct sgtbuf *src,
				struct sgtbuf *dst)
{
	enum CAAM_Status retstatus;

	struct jr_jobctx jobctx  = {0};
	descPointer_t    desc    = ctx->descriptor;
	uint8_t          desclen = 0;

	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));

	if (keyid == NEED_KEY1) {
		/* Build the descriptor */
		desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
			    ctx->key1.length));
		desc_add_ptr(desc, ctx->key1.paddr);

	} else if (keyid == NEED_KEY2) {
		/* Build the descriptor */
		desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
			    ctx->key2.length));
		desc_add_ptr(desc, ctx->key2.paddr);
	}

	/* If there is a context register load it */
	if ((ctx->ctx.length) && (ctx->alg->size_ctx)) {
		desc_add_word(desc, LD_NOIMM_OFF(CLASS_1, REG_CTX,
				ctx->ctx.length, ctx->alg->ctx_offset));
		desc_add_ptr(desc, ctx->ctx.paddr);
		/* Operation with the direction */
		desc_add_word(desc, CIPHER_INIT(ctx->alg->type, encrypt));
	} else {
		/* Operation with the direction */
		desc_add_word(desc, CIPHER_INITFINAL(ctx->alg->type,
				encrypt));
	}

	/* Load the source data */
	if (src->sgt_type) {
		desc_add_word(desc, FIFO_LD_SGT(CLASS_1, MSG, LAST_C1,
				(src->buf[0].length + src->buf[1].length)));
		desc_add_ptr(desc, virt_to_phys(src->sgt));
		caam_cache_op_sgt(TEE_CACHECLEAN, src);
	} else {
		if (src->buf->length > FIFO_LOAD_MAX) {
			desc_add_word(desc, FIFO_LD_EXT(CLASS_1, MSG, LAST_C1));
			desc_add_ptr(desc, src->buf->paddr);
			desc_add_word(desc, src->buf->length);
		} else {
			desc_add_word(desc, FIFO_LD(CLASS_1, MSG, LAST_C1,
					src->buf->length));
			desc_add_ptr(desc, src->buf->paddr);
		}
		cache_operation(TEE_CACHECLEAN, src->buf->data,
				src->buf->length);
	}

	if (dst) {
		if (dst->sgt_type) {
			/* Store the destination data */
			desc_add_word(desc, FIFO_ST_SGT(MSG_DATA,
					(dst->buf[0].length +
					 dst->buf[1].length)));
			desc_add_ptr(desc, virt_to_phys(dst->sgt));
			caam_cache_op_sgt(TEE_CACHEFLUSH, dst);
		} else {
			/* Store the destination data */
			if (dst->buf->length > FIFO_STORE_MAX) {
				desc_add_word(desc, FIFO_ST_EXT(MSG_DATA));
				desc_add_ptr(desc, dst->buf->paddr);
				desc_add_word(desc, dst->buf->length);
			} else {
				desc_add_word(desc, FIFO_ST(MSG_DATA,
					    dst->buf->length));
				desc_add_ptr(desc, dst->buf->paddr);
			}

			if (dst->buf->nocache == 0)
				cache_operation(TEE_CACHEFLUSH, dst->buf->data,
					dst->buf->length);
		}
	}

	if ((ctx->ctx.length) && (ctx->alg->size_ctx)) {
		if (savectx) {
			/* Store the context */
			desc_add_word(desc, ST_NOIMM_OFF(CLASS_1, REG_CTX,
					ctx->ctx.length, ctx->alg->ctx_offset));
			desc_add_ptr(desc, ctx->ctx.paddr);
		}

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
			ctx->ctx.length);
	}
	desclen = desc_get_len(desc);
	if (desclen > MAX_DESC_ENTRIES)	{
		CIPHER_TRACE("Descriptor Size too short (%d vs %d)",
					desclen, MAX_DESC_ENTRIES);
		panic();
	}

	CIPHER_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("CAAM return 0x%"PRIx32" Status 0x%08"PRIx32"",
					retstatus, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	return retstatus;
}

/**
 * @brief   Allocate the SW cipher data context
 *
 * @param[in/out]  ctx         Caller context variable
 * @param[in]      algo        Algorithm ID of the context
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 */
static TEE_Result do_allocate(void **ctx, enum drvcrypt_cipher_id algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct cipherdata      *cipherdata = NULL;
	const struct cipheralg *alg;

	CIPHER_TRACE("Allocate Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	cipherdata = caam_alloc(sizeof(struct cipherdata));
	if (!cipherdata) {
		CIPHER_TRACE("Allocation Cipher data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the descriptor */
	cipherdata->descriptor = caam_alloc_desc(MAX_DESC_ENTRIES);
	if (!cipherdata->descriptor) {
		CIPHER_TRACE("Allocation descriptor error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err_allocate;
	}

	/* Setup the algorithm id and constants reference */
	cipherdata->algo_id = algo;

	switch (DRV_CIPHER_ID(algo)) {
	case DRV_AES_ID:
		CIPHER_TRACE("AES 0x%x", algo);
		alg = aes_alg;
		break;

	case DRV_DES_ID:
		CIPHER_TRACE("DES 0x%x", algo);
		alg = des_alg;
		break;

	case DRV_DES3_ID:
		CIPHER_TRACE("DES3 0x%x", algo);
		alg = des3_alg;
		break;

	default:
		goto err_allocate;
	}

	/* Setup the Algorithm pointer */
	cipherdata->alg = &alg[algo - DRV_CIPHER_ID(algo)];

	/* Initialize the block buffer */
	cipherdata->blockbuf.max = cipherdata->alg->size_block;

	*ctx = cipherdata;

	return TEE_SUCCESS;

err_allocate:
	caam_free_desc(&cipherdata->descriptor);
	caam_free(cipherdata);

	return ret;
}

/**
 * @brief   Free the internal cipher data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free_intern(struct cipherdata *ctx)
{
	CIPHER_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

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

/**
 * @brief   Free the SW Cipher data context
 *
 * @param[in] ctx    Caller context variable
 *
 */
static void do_free(void *ctx)
{
	CIPHER_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(ctx);
	}
}

/**
 * @brief   Copy Software Cipher Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void do_cpy_state(void *dst_ctx, void *src_ctx)
{
	struct cipherdata *dst = dst_ctx;
	struct cipherdata *src = src_ctx;

	CIPHER_TRACE("Copy State context (0x%"PRIxPTR") to (0x%"PRIxPTR")",
			 (uintptr_t)src_ctx, (uintptr_t)dst_ctx);

	dst->algo_id = src->algo_id;
	dst->alg     = src->alg;
	dst->encrypt = src->encrypt;

	if (src->blockbuf.filled) {
		struct drvcrypt_buf srcdata = {
				.data = src->blockbuf.buf.data,
				.length = src->blockbuf.filled};
		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	if (src->key1.length) {
		struct drvcrypt_buf key1 = {
				.data   = src->key1.data,
				.length = src->key1.length};
		copy_ctx_data(&dst->key1, &key1);
	}

	if (src->key2.length) {
		struct drvcrypt_buf key2 = {
				.data   = src->key2.data,
				.length = src->key2.length};
		copy_ctx_data(&dst->key2, &key2);
	}

	if (src->ctx.length) {
		struct drvcrypt_buf ctx = {
				.data   = src->ctx.data,
				.length = src->ctx.length};
		copy_ctx_data(&dst->ctx, &ctx);
	}

	if (src->tweak.length) {
		struct drvcrypt_buf tweak = {
				.data   = src->tweak.data,
				.length = src->tweak.length};
		copy_ctx_data(&dst->tweak, &tweak);
	}

}

/**
 * @brief   Get the algorithm block size
 *
 * @param[in]  algo        Algorithm ID
 * @param[out] size        Block size of the algorithm
 *
 * @retval TEE_SUCCESS     Success
 */
static TEE_Result do_get_blocksize(enum drvcrypt_cipher_id algo, size_t *size)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	size_t       size_block = 0;
	const struct cipheralg *alg;

	switch (DRV_CIPHER_ID(algo)) {
	case DRV_AES_ID:
		alg = aes_alg;
		break;

	case DRV_DES_ID:
		alg = des_alg;
		break;

	case DRV_DES3_ID:
		alg = des3_alg;
		break;

	default:
		return ret;
	}

	size_block = alg[algo - DRV_CIPHER_ID(algo)].size_block;

	if (size_block) {
		*size = size_block;
		ret = TEE_SUCCESS;
	}

	return ret;
}

/**
 * @brief   Initialization of the cipher operation
 *
 * @param[in] dinit  Data initialization object
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result do_init(struct drvcrypt_cipher_init *dinit)
{
	TEE_Result       ret = TEE_ERROR_BAD_PARAMETERS;
	enum CAAM_Status retstatus;

	struct cipherdata      *cipherdata = dinit->ctx;
	const struct cipheralg *alg;

	CIPHER_TRACE("Algo %d - %s", cipherdata->algo_id,
				(dinit->encrypt ? "Encrypt" : " Decrypt"));

	alg = cipherdata->alg;

	/* Check if all required keys are defined */
	if (alg->require_key & NEED_KEY1) {
		if ((!dinit->key1.data) || (dinit->key1.length == 0))
			goto exit_init;

		if (do_check_keysize(&alg->def_key, dinit->key1.length) !=
			CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 1 size");
			goto exit_init;
		}

		/* Copy the key 1 */
		retstatus = copy_ctx_data(&cipherdata->key1, &dinit->key1);
		CIPHER_TRACE("Copy Key 1 returned %d", retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_KEY2) {
		if ((!dinit->key2.data) || (dinit->key2.length == 0))
			goto exit_init;

		if (do_check_keysize(&alg->def_key, dinit->key2.length) !=
			CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 2 size");
			goto exit_init;
		}

		/* Copy the key 2 */
		retstatus = copy_ctx_data(&cipherdata->key2, &dinit->key2);
		CIPHER_TRACE("Copy Key 2 returned %d", retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_IV) {
		if ((!dinit->iv.data) || (dinit->iv.length == 0))
			goto exit_init;

		if (dinit->iv.length != alg->size_ctx) {
			CIPHER_TRACE("Bad IV size %d (expected %d)",
					dinit->iv.length, alg->size_ctx);
			goto exit_init;
		}

		CIPHER_TRACE("Allocate CAAM Context Register (%d bytes)",
					alg->size_ctx);

		/* Copy the IV into the context register */
		retstatus = copy_ctx_data(&cipherdata->ctx, &dinit->iv);
		CIPHER_TRACE("Copy IV returned %d", retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_TWEAK) {
		/* This is accepted to start with a NULL Tweak */
		if (dinit->iv.length != 0) {
			if (dinit->iv.length != alg->size_block) {
				CIPHER_TRACE("Bad tweak 2 size");
				goto exit_init;
			}

			/* Copy the tweak */
			retstatus = copy_ctx_data(&cipherdata->tweak,
				&dinit->iv);
			CIPHER_TRACE("Copy Tweak returned %d", retstatus);

			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto exit_init;
			}
		} else {
			/* Create tweak 0's */
			if (!cipherdata->tweak.data) {
				/*
				 * Allocate the destination buffer and
				 * fill it with 0's
				 */
				ret = caam_alloc_align_buf(&cipherdata->tweak,
					alg->size_block);
				if (ret != CAAM_NO_ERROR)
					return ret;
			} else {
				/* Fill it with 0's */
				memset(cipherdata->tweak.data, 0,
					cipherdata->tweak.length);

				/* Push data to physical memory */
				cache_operation(TEE_CACHEFLUSH,
					cipherdata->tweak.data,
					cipherdata->tweak.length);
			}
		}
	}

	/* Save the operation direction */
	cipherdata->encrypt         = dinit->encrypt;
	cipherdata->blockbuf.filled = 0;

	ret = TEE_SUCCESS;

exit_init:
	if (ret != TEE_SUCCESS) {
		/* Free the internal context in case of error */
		do_free_intern(cipherdata);
	}

	return ret;
}

/**
 * @brief   Update of the cipher operation in streaming mode, meaning
 *          doing partial intermediate block.\n
 *          If there is a context, the context is saved only when a
 *          full block is done.\n
 *          The partial block (if not the last block) is encrypted or
 *          decrypted to return the result and it's saved to be concatened
 *          to next data to rebuild a full block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_update_streaming(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret;
	enum CAAM_Status retstatus;

	struct cipherdata *ctx = dupdate->ctx;

	struct caambuf srcbuf = {0};
	struct caambuf dstbuf = {0};
	struct sgtbuf src = {0};
	struct sgtbuf dst = {0};

	paddr_t psrc;

	size_t fullSize;
	size_t size_topost;
	size_t size_todo;
	size_t size_indone = 0;

	int realloc = 0;
	struct caambuf dst_align = {0};

	CIPHER_TRACE("Algo %d length=%d - %s", ctx->algo_id,
				dupdate->src.length,
				(ctx->encrypt ? "Encrypt" : " Decrypt"));

	realloc = caam_realloc_align(dupdate->dst.data, &dst_align,
			dupdate->dst.length);
	if (realloc == (-1)) {
		CIPHER_TRACE("Destination buffer reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_streaming;
	}

	psrc = virt_to_phys(dupdate->src.data);

	/* Check the payload/cipher physical addresses */
	if (!psrc) {
		CIPHER_TRACE("Bad Addr (src 0x%"PRIxPA")", psrc);
		ret = TEE_ERROR_GENERIC;
		goto end_streaming;
	}

	/* Calculate the total data to be handled */
	fullSize    = ctx->blockbuf.filled + dupdate->src.length;
	size_topost = fullSize % ctx->alg->size_block;

	/* Total size that is a cipher block multiple */
	size_todo   = fullSize - size_topost;

	CIPHER_TRACE("FullSize %d - posted %d - todo %d",
			fullSize, size_topost, size_todo);

	/* If there is full block to do, do them first */
	if (size_todo) {
		size_indone = size_todo - ctx->blockbuf.filled;

		/*
		 * If there is data saved in the temporary buffer,
		 * redo it to generate and increment cipher context
		 * but use trash destination for the data already
		 * computed
		 */
		if (ctx->blockbuf.filled != 0) {
			src.number   = 2;
			src.sgt_type = true;
			dst.number   = 2;
			dst.sgt_type = true;
			retstatus = caam_sgtbuf_alloc(&src);
			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_GENERIC;
				goto end_streaming;
			}

			retstatus = caam_sgtbuf_alloc(&dst);
			if (retstatus != CAAM_NO_ERROR) {
				caam_sgtbuf_free(&src);
				ret = TEE_ERROR_GENERIC;
				goto end_streaming;
			}

			src.buf[0].data   = ctx->blockbuf.buf.data;
			src.buf[0].length = ctx->blockbuf.filled;
			src.buf[1].data   = dupdate->src.data;
			src.buf[1].length = (dupdate->src.length -
				size_topost);

			dst.buf[0].data   = ctx->blockbuf.buf.data;
			dst.buf[0].length = ctx->blockbuf.filled;
			dst.buf[1].data   = dst_align.data;
			dst.buf[1].length = (dupdate->dst.length -
				size_topost);
			dst.buf[1].nocache = dst_align.nocache;

#ifndef ARM64
			src.sgt[0].ptr_ls = ctx->blockbuf.buf.paddr;
			src.sgt[0].length = ctx->blockbuf.filled;
			src.sgt[1].ptr_ls = psrc;
			src.sgt[1].length = (dupdate->src.length -
				size_topost);
			src.sgt[1].final  = 1;

			dst.sgt[0].ptr_ls = ctx->blockbuf.buf.paddr;
			dst.sgt[0].length = ctx->blockbuf.filled;
			dst.sgt[1].ptr_ls = dst_align.paddr;
			dst.sgt[1].length = (dupdate->dst.length -
				size_topost);
			dst.sgt[1].final  = 1;
#else
			src.sgt[0].ptr_ls =
			    (uint32_t)(ctx->blockbuf.buf.paddr);
			src.sgt[0].ptr_ms =
			    (uint32_t)(ctx->blockbuf.buf.paddr >> 32);
			src.sgt[0].length = ctx->blockbuf.filled;
			src.sgt[1].ptr_ls = (uint32_t)(psrc);
			src.sgt[1].ptr_ms = (uint32_t)(psrc >> 32);
			src.sgt[1].length = (dupdate->src.length -
				size_topost);
			src.sgt[1].final  = 1;

			dst.sgt[0].ptr_ls =
			    (uint32_t)(ctx->blockbuf.buf.paddr);
			dst.sgt[0].ptr_ms =
			    (uint32_t)(ctx->blockbuf.buf.paddr >> 32);
			dst.sgt[0].length = ctx->blockbuf.filled;
			dst.sgt[1].ptr_ls = (uint32_t)(dst_align.paddr);
			dst.sgt[1].ptr_ms = (uint32_t)(dst_align.paddr >> 32);
			dst.sgt[1].length = (dupdate->dst.length -
				size_topost);
			dst.sgt[1].final  = 1;
#endif
			ctx->blockbuf.filled = 0;
		} else {
			src.sgt      = NULL;
			src.buf      = &srcbuf;
			src.number   = 1;
			src.sgt_type = false;

			dst.sgt      = NULL;
			dst.buf      = &dstbuf;
			dst.number   = 1;
			dst.sgt_type = false;

			/* Do all complete blocks of input source */
			srcbuf.data   = dupdate->src.data;
			srcbuf.length = size_todo;
			srcbuf.paddr  = psrc;

			dstbuf.data    = dst_align.data;
			dstbuf.length  = size_todo;
			dstbuf.paddr   = dst_align.paddr;
			dstbuf.nocache = dst_align.nocache;
		}

		retstatus = do_block(ctx, true, NEED_KEY1, ctx->encrypt,
			&src, &dst);

		if (src.sgt_type)
			caam_sgtbuf_free(&src);

		if (dst.sgt_type)
			caam_sgtbuf_free(&dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		CIPHER_DUMPBUF("Source", dupdate->src.data,
				(dupdate->src.length - size_topost));
		CIPHER_DUMPBUF("Result", dst_align.data,
				(dupdate->dst.length - size_topost));
	}

	if (size_topost) {
		CIPHER_TRACE("Save input data %d bytes (done %d)",
				size_topost, size_indone);

		retstatus = caam_cpy_block_src(&ctx->blockbuf,
				&dupdate->src, size_indone);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		src.sgt      = NULL;
		src.buf      = &srcbuf;
		src.number   = 1;
		src.sgt_type = false;

		dst.sgt      = NULL;
		dst.buf      = &dstbuf;
		dst.number   = 1;
		dst.sgt_type = false;

		/* Do partial blocks of input source */
		srcbuf.data   = ctx->blockbuf.buf.data;
		srcbuf.length = ctx->blockbuf.filled;
		srcbuf.paddr  = ctx->blockbuf.buf.paddr;

		dstbuf.data    = dst_align.data + size_indone;
		dstbuf.length  = ctx->blockbuf.filled;
		dstbuf.paddr   = dst_align.paddr + size_indone;
		dstbuf.nocache = dst_align.nocache;

		retstatus = do_block(ctx, false, NEED_KEY1, ctx->encrypt,
			&src, &dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		CIPHER_DUMPBUF("Source", ctx->blockbuf.buf.data,
					ctx->blockbuf.filled);
		CIPHER_DUMPBUF("Result", dst.buf->data,
					ctx->blockbuf.filled);
	}

	if (dst_align.nocache == 0)
		cache_operation(TEE_CACHEINVALIDATE, dst_align.data,
				dupdate->dst.length);

	if (realloc)
		memcpy(dupdate->dst.data, dst_align.data, dupdate->dst.length);

	ret = TEE_SUCCESS;

end_streaming:
	if (realloc == 1)
		caam_free_buf(&dst_align);

	return ret;
}

/**
 * @brief   Update of the cipher operation with complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_update_cipher(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret;
	enum CAAM_Status retstatus;

	struct cipherdata *ctx = dupdate->ctx;

	struct caambuf srcbuf = {0};
	struct caambuf dstbuf = {0};
	struct sgtbuf src = {
		.sgt      = NULL,
		.buf      = &srcbuf,
		.number   = 1,
		.sgt_type = false};
	struct sgtbuf dst = {
		.sgt      = NULL,
		.buf      = &dstbuf,
		.number   = 1,
		.sgt_type = false};

	paddr_t psrc;

	int realloc = 0;
	struct caambuf dst_align = {0};

	uint32_t nbBuf  = 0;
	size_t   offset = 0;

	CIPHER_TRACE("Algo %d length=%d - %s", ctx->algo_id,
				dupdate->src.length,
				(ctx->encrypt ? "Encrypt" : " Decrypt"));

	/* Check the length of the payload/cipher */
	if ((dupdate->src.length < ctx->alg->size_block) ||
		(dupdate->src.length % ctx->alg->size_block)) {
		CIPHER_TRACE("Bad payload/cipher size %d bytes",
					dupdate->src.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * If the output memory area is cacheable and the size of
	 * buffer is bigger than MAX_CIPHER_BUFFER, calculate
	 * the number of buffer to do (prevent output reallocation
	 * buffer on cache alignment to fail
	 */
	if ((dupdate->dst.length > MAX_CIPHER_BUFFER) &&
		(core_vbuf_is(CORE_MEM_CACHED, dupdate->dst.data,
					  dupdate->dst.length))) {
		nbBuf = dupdate->dst.length / MAX_CIPHER_BUFFER;

		retstatus = caam_alloc_align_buf(&dst_align, MAX_CIPHER_BUFFER);
		if (retstatus != CAAM_NO_ERROR) {
			CIPHER_TRACE("Destination buffer allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_cipher;
		}
		realloc = 1;
	} else {
		realloc = caam_realloc_align(dupdate->dst.data, &dst_align,
				dupdate->dst.length);
		if (realloc == (-1)) {
			CIPHER_TRACE("Destination buffer reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_cipher;
		}
	}

	psrc = virt_to_phys(dupdate->src.data);

	/* Check the payload/cipher physical addresses */
	if (!psrc) {
		CIPHER_TRACE("Bad Addr (src 0x%"PRIxPA")", psrc);
		ret = TEE_ERROR_GENERIC;
		goto end_cipher;
	}

	srcbuf.data   = dupdate->src.data;
	srcbuf.length = dupdate->src.length;
	srcbuf.paddr  = psrc;

	dstbuf.data    = dst_align.data;
	dstbuf.length  = dupdate->dst.length;
	dstbuf.paddr   = dst_align.paddr;
	dstbuf.nocache = dst_align.nocache;

	if (nbBuf > 0) {
		srcbuf.length = MAX_CIPHER_BUFFER;
		dstbuf.length = MAX_CIPHER_BUFFER;

		do {
			srcbuf.data  += offset;
			srcbuf.paddr += offset;

			CIPHER_TRACE("Do Idx=%d, offset %d", nbBuf, offset);
			retstatus = do_block(ctx, true, NEED_KEY1, ctx->encrypt,
					&src, &dst);

			if (retstatus == CAAM_NO_ERROR) {
				cache_operation(TEE_CACHEINVALIDATE,
					dst_align.data, MAX_CIPHER_BUFFER);

				memcpy(dupdate->dst.data + offset,
					dst_align.data, MAX_CIPHER_BUFFER);
			} else {
				ret = TEE_ERROR_GENERIC;
				goto end_cipher;
			}

			offset += MAX_CIPHER_BUFFER;
		} while (--nbBuf);
	}

	if ((dupdate->src.length - offset) > 0) {
		CIPHER_TRACE("Do Last %d offset %d",
			dupdate->src.length - offset, offset);
		srcbuf.data  += offset;
		srcbuf.length = (dupdate->src.length - offset);
		srcbuf.paddr += offset;

		dstbuf.length = (dupdate->dst.length - offset);

		retstatus = do_block(ctx, true, NEED_KEY1, ctx->encrypt,
			&src, &dst);

		if (retstatus == CAAM_NO_ERROR) {
			if (dst_align.nocache == 0)
				cache_operation(TEE_CACHEINVALIDATE,
					dst_align.data, dstbuf.length);

			if (realloc)
				memcpy(dupdate->dst.data + offset,
					dst_align.data, dstbuf.length);
			ret = TEE_SUCCESS;
		} else {
			ret = TEE_ERROR_GENERIC;
		}
	} else {
		ret = TEE_SUCCESS;
	}

end_cipher:
	if (realloc == 1)
		caam_free_buf(&dst_align);

	return ret;
}

/**
 * @brief   Update of the cipher operation of complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 * @retval TEE_ERROR_SHORT_BUFFER    Output buffer too short
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_update_mac(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result       ret = TEE_ERROR_BAD_PARAMETERS;
	enum CAAM_Status retstatus;

	struct cipherdata *ctx = dupdate->ctx;

	struct caambuf srcbuf = {0};
	struct caambuf dstbuf = {0};
	struct sgtbuf src = {
		.sgt      = NULL,
		.buf      = &srcbuf,
		.number   = 1,
		.sgt_type = false};
	struct sgtbuf dst = {
		.sgt      = NULL,
		.buf      = &dstbuf,
		.number   = 1,
		.sgt_type = false};
	struct sgtbuf *dst_cipher = NULL;

	struct drvcrypt_buf indata_topost = {0};

	size_t fullSize;
	size_t size_topost;
	size_t size_todo;

	int realloc = 0;
	struct caambuf dst_align = {0};

	CIPHER_TRACE("Algo %d length=%d - %s", ctx->algo_id,
				dupdate->src.length,
				(ctx->encrypt ? "Encrypt" : " Decrypt"));

	/* Calculate the total data to be handled */
	fullSize    = ctx->blockbuf.filled + dupdate->src.length;
	size_topost = fullSize % ctx->alg->size_block;

	/* Total size that is a cipher block multiple */
	size_todo   = fullSize - size_topost;

	CIPHER_TRACE("FullSize %d - posted %d - todo %d",
			fullSize, size_topost, size_todo);

	if (dupdate->src.length) {
		if (!dupdate->src.data)
			return ret;

		srcbuf.data   = dupdate->src.data;
		srcbuf.length = dupdate->src.length;
		srcbuf.paddr  = virt_to_phys(dupdate->src.data);

		if (!srcbuf.paddr) {
			CIPHER_TRACE("Bad src address");
			return TEE_ERROR_GENERIC;
		}
	}

	if (dupdate->last) {
		if (!dupdate->dst.data)
			return ret;

		/* Check if the digest size is big enough */
		if (dupdate->dst.length < ctx->alg->size_block)
			return TEE_ERROR_SHORT_BUFFER;

		if (size_todo) {
			realloc = caam_realloc_align(dupdate->dst.data,
				&dst_align,
				dupdate->dst.length);
			if (realloc == (-1)) {
				CIPHER_TRACE("Dest buffer reallocation error");
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto end_mac;
			}

			dstbuf.data    = dst_align.data;
			dstbuf.length  = dupdate->dst.length;
			dstbuf.paddr   = dst_align.paddr;
			dstbuf.nocache = dst_align.nocache;

			dst_cipher = &dst;
		}
	}

	if (size_topost) {
		indata_topost.data   = dupdate->src.data;
		indata_topost.length = size_topost;
	}

	if (size_todo) {
		/*
		 * Check first if there is some data saved to complete the
		 * buffer.
		 */
		if (ctx->blockbuf.filled != 0) {
			/* Complete temporary buffer to make a full block */
			struct drvcrypt_buf indata = {
				.data   = (uint8_t *)srcbuf.data,
				.length = srcbuf.length};

			struct caambuf tmpbuf = {0};
			struct sgtbuf tmpsrc = {
				.sgt      = NULL,
				.buf      = &tmpbuf,
				.number   = 1,
				.sgt_type = false};

			tmpbuf.data   = ctx->blockbuf.buf.data,
			tmpbuf.length = ctx->alg->size_block,
			tmpbuf.paddr  = ctx->blockbuf.buf.paddr,

			srcbuf.data  += (ctx->alg->size_block -
				ctx->blockbuf.filled);
			srcbuf.paddr += (ctx->alg->size_block -
				ctx->blockbuf.filled);
			CIPHER_TRACE("Offset src %d",
				(ctx->alg->size_block - ctx->blockbuf.filled));

			retstatus = caam_cpy_block_src(&ctx->blockbuf,
				&indata, 0);
			if (retstatus != CAAM_NO_ERROR)
				return TEE_ERROR_GENERIC;

			ctx->blockbuf.filled = 0;

			retstatus = do_block(ctx, true, NEED_KEY1, true,
				&tmpsrc, dst_cipher);

			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_GENERIC;
				goto end_mac;
			}

#ifdef DBG_BUF_CIPHER
			CIPHER_DUMPBUF("Source", tmpbuf.data, tmpbuf.length);
			if (dst_cipher) {
				CIPHER_DUMPBUF("Cipher",
					dstbuf.data, dstbuf.length);
			}

			CIPHER_DUMPBUF("Ctx", ctx->ctx.data, ctx->ctx.length);
#endif
			size_todo -= ctx->alg->size_block;
		}

		src.buf->length = ctx->alg->size_block;

		while (size_todo) {
			retstatus = do_block(ctx, true, NEED_KEY1, true,
				&src, dst_cipher);
			if (retstatus != CAAM_NO_ERROR)
				return TEE_ERROR_GENERIC;

			CIPHER_DUMPBUF("Source", srcbuf.data,
				ctx->alg->size_block);
			CIPHER_DUMPBUF("Ctx", ctx->ctx.data, ctx->ctx.length);

			srcbuf.data  += ctx->alg->size_block;
			srcbuf.paddr += ctx->alg->size_block;

			size_todo -= ctx->alg->size_block;
		};

		indata_topost.data = srcbuf.data;
	} else {
		/*
		 * There is no complete block to do:
		 *   - either input size + already saved data < block size
		 *   - or no input data and this is the last block
		 */
		if (dupdate->last) {
			memcpy(dupdate->dst.data, ctx->ctx.data,
					dupdate->dst.length);
			ret = TEE_SUCCESS;
		}
	}

	ret = TEE_SUCCESS;

	if (size_topost) {
		CIPHER_TRACE("Post %d of input len %d",
				size_topost, dupdate->src.length);
		retstatus = caam_cpy_block_src(&ctx->blockbuf,
				&indata_topost, 0);
		if (retstatus != CAAM_NO_ERROR)
			ret = TEE_ERROR_GENERIC;
	}

	if (dst_align.data) {
		if (dst_align.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, dst_align.data,
				dupdate->dst.length);

		if (realloc)
			memcpy(dupdate->dst.data, dst_align.data,
				dupdate->dst.length);
	}

end_mac:
	if (realloc == 1)
		caam_free_buf(&dst_align);

	return ret;
}

/**
 * @brief   Update of the cipher operation for AES CTS mode.
 *          Call the tee_aes_cbc_cts_update function that will either
 *          call AES ECB/CBC algorithm.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 * @retval TEE_ERROR_BAD_STATE       Data length error
 */
static TEE_Result do_update_cts(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret;
	struct crypto_cipher *cipher_ctx;
	void   *cipher_cbc = NULL;
	void   *cipher_ecb = NULL;
	struct cipherdata *in_ctx = dupdate->ctx;
	struct cipherdata *ctx_cbc;
	struct cipherdata *ctx_ecb;

	CIPHER_TRACE("Algo AES CTS length=%d - %s",
				dupdate->src.length,
				(in_ctx->encrypt ? "Encrypt" : " Decrypt"));

	ret = crypto_cipher_alloc_ctx(&cipher_cbc, TEE_ALG_AES_CBC_NOPAD);
	if (ret != TEE_SUCCESS)
		goto end_update_cts;
	cipher_ctx = container_of(cipher_cbc, struct crypto_cipher, cipher_ctx);
	ctx_cbc = cipher_ctx->ctx;

	ret = crypto_cipher_alloc_ctx((void **)&cipher_ecb,
			TEE_ALG_AES_ECB_NOPAD);
	if (ret != TEE_SUCCESS)
		goto end_update_cts;
	cipher_ctx = container_of(cipher_ecb, struct crypto_cipher, cipher_ctx);
	ctx_ecb = cipher_ctx->ctx;

	ctx_cbc->key1.data    = in_ctx->key1.data;
	ctx_cbc->key1.length  = in_ctx->key1.length;
	ctx_cbc->key1.paddr   = in_ctx->key1.paddr;
	ctx_cbc->key1.nocache = in_ctx->key1.nocache;

	ctx_cbc->ctx.data    = in_ctx->ctx.data;
	ctx_cbc->ctx.length  = in_ctx->ctx.length;
	ctx_cbc->ctx.paddr   = in_ctx->ctx.paddr;
	ctx_cbc->ctx.nocache = in_ctx->ctx.nocache;

	ctx_ecb->key1.data    = in_ctx->key1.data;
	ctx_ecb->key1.length  = in_ctx->key1.length;
	ctx_ecb->key1.paddr   = in_ctx->key1.paddr;
	ctx_ecb->key1.nocache = in_ctx->key1.nocache;

	ctx_cbc->encrypt         = in_ctx->encrypt;
	ctx_cbc->blockbuf.filled = 0;
	ctx_ecb->encrypt         = in_ctx->encrypt;
	ctx_ecb->blockbuf.filled = 0;

	ret = tee_aes_cbc_cts_update(cipher_cbc, cipher_ecb,
		(in_ctx->encrypt ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT),
		dupdate->last, dupdate->src.data, dupdate->src.length,
		dupdate->dst.data);

	ctx_cbc->key1.data   = NULL;
	ctx_cbc->key1.length = 0;
	ctx_cbc->ctx.data    = NULL;
	ctx_cbc->ctx.length  = 0;
	ctx_ecb->key1.data   = NULL;
	ctx_ecb->key1.length = 0;

end_update_cts:
	crypto_cipher_free_ctx(cipher_cbc, TEE_ALG_AES_CBC_NOPAD);
	crypto_cipher_free_ctx(cipher_ecb, TEE_ALG_AES_ECB_NOPAD);

	return ret;
}

/**
 * @brief   Update of the cipher operation. Call the algorithm update
 *          function associated.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 */
static TEE_Result do_update(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result  ret;

	struct cipherdata *cipherdata = dupdate->ctx;

	ret = cipherdata->alg->update(dupdate);

	return ret;
}

/**
 * @brief   Finalize of the cipher operation
 *
 * @param[in] ctx    Caller context variable
 */
static void do_final(void *ctx __unused)
{
}

/**
 * @brief   Registration of the Cipher Driver
 */
struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx  = &do_allocate,
	.free_ctx   = &do_free,
	.init       = &do_init,
	.update     = &do_update,
	.final      = &do_final,
	.block_size = &do_get_blocksize,
	.cpy_state  = &do_cpy_state,
};

/**
 * @brief   Initialize the Cipher module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_cipher_init(vaddr_t ctrl_addr __unused)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	if (drvcrypt_register(CRYPTO_CIPHER, &driver_cipher) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
