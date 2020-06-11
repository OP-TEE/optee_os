// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Implementation of Cipher functions
 */
#include <caam_cipher.h>
#include <caam_common.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

#include "local.h"

/*
 * Max Cipher Buffer to encrypt/decrypt at each operation
 */
#define MAX_CIPHER_BUFFER (8 * 1024)

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
				   struct caambuf *indata,
				   struct caambuf *outdata, bool blockbuf)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = ctx->descriptor;
	struct caamsgtbuf src_sgt = {
		.sgt_type = false
	};
	struct caamsgtbuf dst_sgt = {
		.sgt_type = false
	};

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

	/*
	 * Load the source data.
	 * If there is a block of data saved during the previous streaming
	 * updates add it first.
	 * If Source data is a User Data buffer mapped on multiple pages
	 * create a Scatter/Gather table.
	 */
	if (blockbuf)
		retstatus = caam_sgt_build_block_data(&src_sgt, &ctx->blockbuf,
						      indata);
	else
		retstatus = caam_sgt_build_block_data(&src_sgt, NULL, indata);

	if (retstatus != CAAM_NO_ERROR)
		goto exit_cipher_block;

	if (src_sgt.sgt_type) {
		if (src_sgt.length > FIFO_LOAD_MAX) {
			caam_desc_add_word(desc, FIFO_LD_SGT_EXT(CLASS_1, MSG,
								 LAST_C1));
			caam_desc_add_ptr(desc, virt_to_phys(src_sgt.sgt));
			caam_desc_add_word(desc, src_sgt.length);
		} else {
			caam_desc_add_word(desc,
					   FIFO_LD_SGT(CLASS_1, MSG, LAST_C1,
						       src_sgt.length));
			caam_desc_add_ptr(desc, virt_to_phys(src_sgt.sgt));
		}
		caam_sgt_cache_op(TEE_CACHECLEAN, &src_sgt);
	} else {
		if (src_sgt.length > FIFO_LOAD_MAX) {
			caam_desc_add_word(desc,
					   FIFO_LD_EXT(CLASS_1, MSG, LAST_C1));
			caam_desc_add_ptr(desc, src_sgt.buf->paddr);
			caam_desc_add_word(desc, src_sgt.length);
		} else {
			caam_desc_add_word(desc, FIFO_LD(CLASS_1, MSG, LAST_C1,
							 src_sgt.length));
			caam_desc_add_ptr(desc, src_sgt.buf->paddr);
		}

		if (!src_sgt.buf->nocache)
			cache_operation(TEE_CACHECLEAN, src_sgt.buf->data,
					src_sgt.length);
	}

	/* No output data - just create/update operation context */
	if (!outdata)
		goto handle_context;

	/*
	 * Output data storage.
	 * In case of streaming, part of the output data is stored in the
	 * backup block for the next operation.
	 * If Output data is a User Data buffer mapped on multiple pages
	 * create a Scatter/Gather table.
	 */
	if (blockbuf)
		retstatus = caam_sgt_build_block_data(&dst_sgt, &ctx->blockbuf,
						      outdata);
	else
		retstatus = caam_sgt_build_block_data(&dst_sgt, NULL, outdata);

	if (retstatus != CAAM_NO_ERROR)
		goto exit_cipher_block;

	if (dst_sgt.sgt_type) {
		if (dst_sgt.length > FIFO_LOAD_MAX) {
			caam_desc_add_word(desc, FIFO_ST_SGT_EXT(MSG_DATA));
			caam_desc_add_ptr(desc, virt_to_phys(dst_sgt.sgt));
			caam_desc_add_word(desc, dst_sgt.length);
		} else {
			caam_desc_add_word(desc, FIFO_ST_SGT(MSG_DATA,
							     dst_sgt.length));
			caam_desc_add_ptr(desc, virt_to_phys(dst_sgt.sgt));
		}
		caam_sgt_cache_op(TEE_CACHEFLUSH, &dst_sgt);
	} else {
		if (dst_sgt.length > FIFO_LOAD_MAX) {
			caam_desc_add_word(desc, FIFO_ST_EXT(MSG_DATA));
			caam_desc_add_ptr(desc, dst_sgt.buf->paddr);
			caam_desc_add_word(desc, dst_sgt.length);
		} else {
			caam_desc_add_word(desc,
					   FIFO_ST(MSG_DATA, dst_sgt.length));
			caam_desc_add_ptr(desc, dst_sgt.buf->paddr);
		}

		if (!dst_sgt.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, dst_sgt.buf->data,
					dst_sgt.length);
	}

handle_context:
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

exit_cipher_block:
	if (src_sgt.sgt_type)
		caam_sgtbuf_free(&src_sgt);

	if (dst_sgt.sgt_type)
		caam_sgtbuf_free(&dst_sgt);

	return retstatus;
}

/*
 * Checks if the algorithm @algo is supported and returns the
 * local algorithm entry in the corresponding cipher array
 */
static const struct cipheralg *get_cipheralgo(uint32_t algo)
{
	unsigned int algo_id = 0;
	unsigned int algo_md = 0;
	const struct cipheralg *ca = NULL;

	/* Extract the algorithms fields */
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	algo_md = TEE_ALG_GET_CHAIN_MODE(algo);

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

/*
 * Free the SW Cipher data context
 *
 * @ctx    Caller context variable or NULL
 */
static void do_free(void *ctx)
{
	CIPHER_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(ctx);
	}
}

/*
 * Copy Software Cipher Context
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void do_copy_state(void *dst_ctx, void *src_ctx)
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

/*
 * Initialization of the cipher operation
 *
 * @dinit  Data initialization object
 */
static TEE_Result do_init(struct drvcrypt_cipher_init *dinit)
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

				/* Push data to physical memory */
				cache_operation(TEE_CACHEFLUSH,
						cipherdata->tweak.data,
						cipherdata->tweak.length);
			}
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
	struct caambuf srcbuf = { };
	struct caambuf dstbuf = { };
	paddr_t psrc = 0;
	size_t fullSize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_indone = 0;
	int realloc = 0;
	struct caambuf dst_align = { };

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     ctx->encrypt ? "Encrypt" : "Decrypt");

	realloc = caam_set_or_alloc_align_buf(dupdate->dst.data, &dst_align,
					      dupdate->dst.length);
	if (realloc == -1) {
		CIPHER_TRACE("Destination buffer reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	psrc = virt_to_phys(dupdate->src.data);

	/* Check the payload/cipher physical addresses */
	if (!psrc) {
		CIPHER_TRACE("Bad Addr (src 0x%" PRIxPA ")", psrc);
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Calculate the total data to be handled */
	fullSize = ctx->blockbuf.filled + dupdate->src.length;
	size_topost = fullSize % ctx->alg->size_block;

	if (fullSize < ctx->alg->size_block) {
		size_topost = dupdate->src.length;
	} else {
		size_topost = fullSize % ctx->alg->size_block;
		/* Total size that is a cipher block multiple */
		size_todo = fullSize - size_topost;
	}

	CIPHER_TRACE("FullSize %zu - posted %zu - todo %zu", fullSize,
		     size_topost, size_todo);

	/* If there is full block to do, do them first */
	if (size_todo) {
		size_indone = size_todo - ctx->blockbuf.filled;

		if (!caam_mem_is_cached_buf(dupdate->src.data,
					    dupdate->src.length))
			srcbuf.nocache = 1;

		/*
		 * If there are data saved in the temporary buffer,
		 * redo it to generate and increment cipher context.
		 */
		if (ctx->blockbuf.filled) {
			srcbuf.data = dupdate->src.data;
			srcbuf.length = (dupdate->src.length - size_topost);
			srcbuf.paddr = psrc;

			dstbuf.data = dst_align.data;
			dstbuf.length = (dupdate->dst.length - size_topost);
			dstbuf.paddr = dst_align.paddr;
			dstbuf.nocache = dst_align.nocache;

			retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
						      ctx->encrypt, &srcbuf,
						      &dstbuf, true);

			ctx->blockbuf.filled = 0;
		} else {
			/* Do all complete blocks of input source */
			srcbuf.data = dupdate->src.data;
			srcbuf.length = size_todo;
			srcbuf.paddr = psrc;

			dstbuf.data = dst_align.data;
			dstbuf.length = size_todo;
			dstbuf.paddr = dst_align.paddr;
			dstbuf.nocache = dst_align.nocache;

			retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
						      ctx->encrypt, &srcbuf,
						      &dstbuf, false);
		}

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		CIPHER_DUMPBUF("Source", dupdate->src.data,
			       dupdate->src.length - size_topost);
		CIPHER_DUMPBUF("Result", dst_align.data,
			       dupdate->dst.length - size_topost);
	}

	if (size_topost) {
		struct caambuf cpysrc = {
			.data = dupdate->src.data,
			.length = dupdate->src.length
		};

		CIPHER_TRACE("Save input data %zu bytes (done %zu)",
			     size_topost, size_indone);

		retstatus = caam_cpy_block_src(&ctx->blockbuf, &cpysrc,
					       size_indone);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		/* Do partial blocks of input source */
		srcbuf.data = ctx->blockbuf.buf.data;
		srcbuf.length = ctx->blockbuf.filled;
		srcbuf.paddr = ctx->blockbuf.buf.paddr;
		srcbuf.nocache = ctx->blockbuf.buf.nocache;

		dstbuf.data = dst_align.data + size_indone;
		dstbuf.length = ctx->blockbuf.filled;
		dstbuf.paddr = dst_align.paddr + size_indone;
		dstbuf.nocache = dst_align.nocache;

		retstatus = caam_cipher_block(ctx, false, NEED_KEY1,
					      ctx->encrypt, &srcbuf, &dstbuf,
					      false);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		CIPHER_DUMPBUF("Source", srcbuf.data, srcbuf.length);
		CIPHER_DUMPBUF("Result", dstbuf.data, dstbuf.length);
	}

	if (!dst_align.nocache)
		cache_operation(TEE_CACHEINVALIDATE, dst_align.data,
				dupdate->dst.length);

	if (realloc)
		memcpy(dupdate->dst.data, dst_align.data, dupdate->dst.length);

	ret = TEE_SUCCESS;

out:
	if (realloc == 1)
		caam_free_buf(&dst_align);

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
	struct caambuf srcbuf = { };
	struct caambuf dstbuf = { };
	int realloc = 0;
	struct caambuf dst_align = { };
	unsigned int nb_buf = 0;
	size_t offset = 0;

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

	/*
	 * If the output memory area is cacheable and the size of
	 * buffer is bigger than MAX_CIPHER_BUFFER, calculate
	 * the number of buffer to do (prevent output reallocation
	 * of a big buffer)
	 */
	if (dupdate->dst.length > MAX_CIPHER_BUFFER &&
	    caam_mem_is_cached_buf(dupdate->dst.data, dupdate->dst.length)) {
		nb_buf = dupdate->dst.length / MAX_CIPHER_BUFFER;

		retstatus = caam_alloc_align_buf(&dst_align, MAX_CIPHER_BUFFER);
		if (retstatus != CAAM_NO_ERROR) {
			CIPHER_TRACE("Destination buffer allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		realloc = 1;
	} else {
		realloc = caam_set_or_alloc_align_buf(dupdate->dst.data,
						      &dst_align,
						      dupdate->dst.length);
		if (realloc == -1) {
			CIPHER_TRACE("Destination buffer reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	srcbuf.data = dupdate->src.data;
	srcbuf.length = dupdate->src.length;
	srcbuf.paddr = virt_to_phys(dupdate->src.data);
	if (!caam_mem_is_cached_buf(dupdate->src.data, dupdate->src.length))
		srcbuf.nocache = 1;

	/* Check the payload/cipher physical addresses */
	if (!srcbuf.paddr) {
		CIPHER_TRACE("Physical Address error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	dstbuf.data = dst_align.data;
	dstbuf.paddr = dst_align.paddr;
	dstbuf.nocache = dst_align.nocache;

	/*
	 * Prepare to do Maximum Cipher Buffer size in case
	 * there input data is more than the supported maximum
	 * cipher size
	 */
	srcbuf.length = MAX_CIPHER_BUFFER;
	dstbuf.length = MAX_CIPHER_BUFFER;

	while (nb_buf--) {
		srcbuf.data += offset;
		srcbuf.paddr += offset;

		CIPHER_TRACE("Do nb_buf=%u, offset %zu", nb_buf, offset);

		retstatus =
			caam_cipher_block(ctx, true, NEED_KEY1, ctx->encrypt,
					  &srcbuf, &dstbuf, false);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		cache_operation(TEE_CACHEINVALIDATE, dstbuf.data,
				dstbuf.length);

		memcpy(dupdate->dst.data + offset, dstbuf.data, dstbuf.length);

		offset += MAX_CIPHER_BUFFER;
	}

	/*
	 * After doing all maximum block, finalize operation
	 * with the remaining data
	 */
	if (dupdate->src.length - offset > 0) {
		CIPHER_TRACE("Do Last %zu offset %zu",
			     dupdate->src.length - offset, offset);
		srcbuf.data += offset;
		srcbuf.length = dupdate->src.length - offset;
		srcbuf.paddr += offset;

		dstbuf.length = dupdate->dst.length - offset;

		retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
					      ctx->encrypt, &srcbuf, &dstbuf,
					      false);

		if (retstatus == CAAM_NO_ERROR) {
			if (!dstbuf.nocache)
				cache_operation(TEE_CACHEINVALIDATE,
						dstbuf.data, dstbuf.length);

			if (realloc)
				memcpy(dupdate->dst.data + offset, dstbuf.data,
				       dstbuf.length);

			ret = TEE_SUCCESS;
		} else {
			ret = TEE_ERROR_GENERIC;
		}
	} else {
		ret = TEE_SUCCESS;
	}

out:
	if (realloc == 1)
		caam_free_buf(&dst_align);

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
	.alloc_ctx = &do_allocate,
	.free_ctx = &do_free,
	.init = &do_init,
	.update = &do_update,
	.final = &do_final,
	.copy_state = &do_copy_state,
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
