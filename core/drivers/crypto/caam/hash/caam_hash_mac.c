// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Implementation of Hashing functions.
 */
#include <caam_hal_ctrl.h>
#include <caam_hash.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_mac.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

#include "local.h"

#ifdef CFG_PHYS_64BIT
#define KEY_REDUCE_DESC_ENTRIES	 10
#define KEY_COMPUTE_DESC_ENTRIES 10
#else
#define KEY_REDUCE_DESC_ENTRIES	 8
#define KEY_COMPUTE_DESC_ENTRIES 8
#endif

static const struct crypto_mac_ops hmac_ops;

/*
 * Format the MAC context to keep the reference to the operation driver.
 */
struct crypto_mac {
	struct crypto_mac_ctx mac_ctx; /* Crypto MAC API context */
	struct hashctx *ctx;	       /* HMAC context */
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
static struct crypto_mac *to_mac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &hmac_ops);

	return container_of(ctx, struct crypto_mac, mac_ctx);
}

/*
 * Reduce key to be a hash algorithm block size maximum
 *
 * @alg     Reference to the algorithm definition
 * @inkey   Key to be reduced
 * @outkey  [out] key resulting
 */
static enum caam_status do_reduce_key(const struct hashalg *alg,
				      struct caambuf *inkey,
				      struct caamsgtbuf *outkey)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caamsgtbuf key_sgt = { .sgt_type = false };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;

	retstatus = caam_sgt_build_block_data(&key_sgt, NULL, inkey);
	if (retstatus != CAAM_NO_ERROR)
		goto out;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(KEY_REDUCE_DESC_ENTRIES);
	if (!desc) {
		retstatus = CAAM_OUT_MEMORY;
		goto out;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, HASH_INITFINAL(alg->type));

	/* Load the input key */
	if (key_sgt.sgt_type) {
		caam_desc_add_word(desc,
				   FIFO_LD_SGT_EXT(CLASS_2, MSG, LAST_C2));
		caam_desc_add_ptr(desc, virt_to_phys(key_sgt.sgt));
		caam_desc_add_word(desc, key_sgt.length);

		caam_sgt_cache_op(TEE_CACHECLEAN, &key_sgt);
	} else {
		caam_desc_add_word(desc, FIFO_LD_EXT(CLASS_2, MSG, LAST_C2));
		caam_desc_add_ptr(desc, key_sgt.buf->paddr);
		caam_desc_add_word(desc, key_sgt.length);

		cache_operation(TEE_CACHECLEAN, key_sgt.buf->data,
				key_sgt.length);
	}

	/* Store key reduced */
	if (outkey->sgt_type) {
		caam_desc_add_word(desc, ST_SGT_NOIMM(CLASS_2, REG_CTX,
						      outkey->length));
		caam_desc_add_ptr(desc, virt_to_phys(outkey->sgt));
		caam_sgt_cache_op(TEE_CACHEFLUSH, outkey);
	} else {
		caam_desc_add_word(desc,
				   ST_NOIMM(CLASS_2, REG_CTX, outkey->length));
		caam_desc_add_ptr(desc, outkey->buf->paddr);

		cache_operation(TEE_CACHEFLUSH, outkey->buf->data,
				outkey->length);
	}

	HASH_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		HASH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

out:
	if (key_sgt.sgt_type)
		caam_sgtbuf_free(&key_sgt);

	caam_free_desc(&desc);

	return retstatus;
}

/*
 * Initialization of the HMAC operation.
 * Split the input key using the CAAM HW HMAC operation
 * Call common initialization operation between hash and HMAC
 *
 * @ctx   Operation software context
 * @key   Input key to compute
 * @len   Key length
 */
static TEE_Result do_hmac_init(struct crypto_mac_ctx *ctx, const uint8_t *key,
			       size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct crypto_mac *mac = to_mac_ctx(ctx);
	struct hashctx *hmac_ctx = mac->ctx;
	const struct hashalg *alg = hmac_ctx->alg;
	struct caambuf inkey = { };
	struct caamsgtbuf key_sgt = { .sgt_type = false };
	struct caambuf hashkey = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;

	/* First initialize the context */
	ret = caam_hash_hmac_init(hmac_ctx);
	if (ret != TEE_SUCCESS)
		return ret;

	HASH_TRACE("split key length %zu", len);

	inkey.data = (uint8_t *)key;
	inkey.length = len;
	inkey.paddr = virt_to_phys(inkey.data);
	if (!inkey.paddr) {
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(KEY_COMPUTE_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	hmac_ctx->key.length = alg->size_key;

	if (len > alg->size_block) {
		HASH_TRACE("Input key must be reduced");

		retstatus = caam_calloc_align_buf(&hashkey, alg->size_digest);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("Reduced Key allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		retstatus = caam_sgt_build_block_data(&key_sgt, NULL, &hashkey);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		retstatus = do_reduce_key(alg, &inkey, &key_sgt);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}
	} else {
		/* Key size is correct use directly the input key */
		retstatus = caam_sgt_build_block_data(&key_sgt, NULL, &inkey);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	/* Load either input key or the reduced input key into key register */
	if (key_sgt.sgt_type) {
		caam_desc_add_word(desc, LD_KEY_SGT_PLAIN(CLASS_2, REG,
							  key_sgt.length));
		caam_desc_add_ptr(desc, virt_to_phys(key_sgt.sgt));
		caam_sgt_cache_op(TEE_CACHECLEAN, &key_sgt);
	} else {
		caam_desc_add_word(desc,
				   LD_KEY_PLAIN(CLASS_2, REG, key_sgt.length));
		caam_desc_add_ptr(desc, key_sgt.buf->paddr);
		cache_operation(TEE_CACHECLEAN, key_sgt.buf->data,
				key_sgt.length);
	}
	/* Split the key */
	caam_desc_add_word(desc, HMAC_INIT_DECRYPT(alg->type));
	caam_desc_add_word(desc, FIFO_LD_IMM(CLASS_2, MSG, LAST_C2, 0));
	/* Store the split key */
	caam_desc_add_word(desc, FIFO_ST(C2_MDHA_SPLIT_KEY_AES_ECB_JKEK,
					 hmac_ctx->key.length));
	caam_desc_add_ptr(desc, hmac_ctx->key.paddr);
	HASH_DUMPDESC(desc);

	cache_operation(TEE_CACHEFLUSH, hmac_ctx->key.data,
			hmac_ctx->key.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		HASH_DUMPBUF("Split Key", hmac_ctx->key.data,
			     hmac_ctx->key.length);

		ret = TEE_SUCCESS;
	} else {
		HASH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	if (key_sgt.sgt_type)
		caam_sgtbuf_free(&key_sgt);

	caam_free_buf(&hashkey);
	caam_free_desc(&desc);

	return ret;
}

/*
 * Update the HMAC operation
 * Call common update operation between hash and HMAC
 *
 * @ctx   Operation Software context
 * @data  Data to hash
 * @len   Data length
 */
static TEE_Result do_hmac_update(struct crypto_mac_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct crypto_mac *mac = to_mac_ctx(ctx);

	return caam_hash_hmac_update(mac->ctx, data, len);
}

/*
 * Finalize the HMAC operation
 * Call common final operation between hash and HMAC
 *
 * @ctx     Operation Software context
 * @digest  [out] Hash digest buffer
 * @len     Digest buffer length
 */
static TEE_Result do_hmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				size_t len)
{
	struct crypto_mac *mac = to_mac_ctx(ctx);

	return caam_hash_hmac_final(mac->ctx, digest, len);
}

/*
 * Free the software context
 * Call common free operation between hash and HMAC
 *
 * @ctx    Caller context variable
 */
static void do_hmac_free(struct crypto_mac_ctx *ctx)
{
	struct crypto_mac *mac = to_mac_ctx(ctx);

	caam_hash_hmac_free(mac->ctx);

	free(mac);
}

/*
 * Copy sofware HMAC context
 * Call common copy operation between hash and HMAC
 *
 * @dst_ctx  [out] Reference the context destination
 * @src_ctx  Reference the context source
 */
static void do_hmac_copy_state(struct crypto_mac_ctx *dst_ctx,
			       struct crypto_mac_ctx *src_ctx)
{
	struct crypto_mac *mac_src = to_mac_ctx(src_ctx);
	struct crypto_mac *mac_dst = to_mac_ctx(dst_ctx);

	return caam_hash_hmac_copy_state(mac_dst->ctx, mac_src->ctx);
}

/*
 * Registration of the HMAC driver
 */
static const struct crypto_mac_ops hmac_ops = {
	.init = do_hmac_init,
	.update = do_hmac_update,
	.final = do_hmac_final,
	.free_ctx = do_hmac_free,
	.copy_state = do_hmac_copy_state,
};

/*
 * Allocate the internal hashing data context
 *
 * @ctx    [out] Caller context reference
 * @algo   Algorithm ID
 */
static TEE_Result caam_hmac_allocate(struct crypto_mac_ctx **ctx, uint32_t algo)
{
	struct crypto_mac *mac = NULL;
	struct hashctx *hmac_ctx = NULL;
	const struct hashalg *alg = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	HASH_TRACE("Allocate Context (%p) algo %" PRId32, ctx, algo);

	*ctx = NULL;

	alg = caam_hash_get_alg(algo);
	if (!alg)
		return TEE_ERROR_NOT_IMPLEMENTED;

	mac = calloc(1, sizeof(*mac));
	if (!mac)
		return TEE_ERROR_OUT_OF_MEMORY;

	hmac_ctx = caam_calloc(sizeof(*hmac_ctx));
	if (!hmac_ctx) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	hmac_ctx->alg = alg;
	mac->mac_ctx.ops = &hmac_ops;
	mac->ctx = hmac_ctx;

	*ctx = &mac->mac_ctx;

	ret = caam_hash_hmac_allocate(hmac_ctx);
	if (ret != TEE_SUCCESS)
		goto err;

	HASH_TRACE("Allocated Context (%p)", hmac_ctx);

	return TEE_SUCCESS;

err:
	free(mac);

	if (hmac_ctx)
		caam_free(hmac_ctx);

	return ret;
}

enum caam_status caam_hmac_init(vaddr_t ctrl_addr)
{
	caam_hash_limit = caam_hal_ctrl_hash_limit(ctrl_addr);

	if (caam_hash_limit != UINT8_MAX &&
	    caam_hal_ctrl_splitkey_support(ctrl_addr)) {
		if (drvcrypt_register_hmac(&caam_hmac_allocate))
			return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}
