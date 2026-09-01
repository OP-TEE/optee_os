// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025-2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/amd/asu_client.h>
#include <drvcrypt_hash.h>
#include <drvcrypt_mac.h>
#include <initcall.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/unwind.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib_ext.h>
#include <string.h>
#include <tee/cache.h>
#include <trace.h>
#include <util.h>

#define ASU_SHA_OPERATION_CMD_ID		0U
/* SHA modes */
#define ASU_SHA_MODE_SHA256			0U
#define ASU_SHA_MODE_SHA384			1U
#define ASU_SHA_MODE_SHA512			2U
#define ASU_SHA_MODE_SHAKE256			4U

/* SHA operation mode */
#define ASU_SHA_START				0x1U
#define ASU_SHA_UPDATE				0x2U
#define ASU_SHA_FINISH				0x4U

/* SHA hash lengths */
#define ASU_SHA_256_HASH_LEN			32U
#define ASU_SHA_384_HASH_LEN			48U
#define ASU_SHA_512_HASH_LEN			64U
#define ASU_SHAKE_256_HASH_LEN			32U
#define ASU_SHAKE_256_MAX_HASH_LEN		136U
#define ASU_DATA_CHUNK_LEN			4096U

#define ASU_DMA_ALIGNMENT			64U

#if defined(CFG_AMD_ASU_HMAC)
/* HMAC command IDs (used as cmdid in asu_create_header) */
#define ASU_HMAC_CMD_SHA2			0U
#define ASU_HMAC_CMD_SHA3			1U

/* SHA type IDs passed to ASUFW */
#define ASU_HMAC_SHA2_TYPE			0x02U
#define ASU_HMAC_SHA3_TYPE			0x03U

/* HMAC operation flags */
#define ASU_HMAC_OP_INIT			0x1U
#define ASU_HMAC_OP_UPDATE			0x2U
#define ASU_HMAC_OP_FINISH			0x4U

#define ASU_HMAC_MAX_KEY_LEN			1024U
#endif /* CFG_AMD_ASU_HMAC */

struct asu_shadev {
	bool sha2_available;
	bool sha3_available;
	/* Control access to engine*/
	struct mutex engine_lock;
};

struct asu_sha_op_cmd {
	uint64_t dataaddr;
	uint64_t hashaddr;
	uint32_t datasize;
	uint32_t hashbufsize;
	uint8_t shamode;
	uint8_t islast;
	uint8_t opflags;
	uint8_t shakereserved;
};

struct asu_hash_ctx {
	struct crypto_hash_ctx hash_ctx; /* Crypto Hash API context */
	struct asu_client_params cparam;
	uint32_t shamode;
	uint32_t shastart;
	uint8_t uniqueid;
	uint8_t module;
};

#if defined(CFG_AMD_ASU_HMAC)

struct asu_hmac_op_cmd {
	uint64_t keyinaddr;
	uint32_t keyinlen;
	uint32_t keyid;
	uint64_t msgaddr;
	uint64_t hmacaddr;
	uint32_t msglen;
	uint32_t hmaclen;
	uint8_t shatype;
	uint8_t shamode;
	uint8_t islast;
	uint8_t opflags;
	uint32_t reserved;
};

struct asu_hmac_result {
	uint8_t buf[ASU_SHA_512_HASH_LEN];
	uint32_t len;
};

struct asu_hmac_ctx {
	struct crypto_mac_ctx mac_ctx;
	struct asu_client_params cparam;
	struct asu_hmac_result result;
	uint8_t *key_buf;
	uint32_t key_len;
	uint32_t hmaclen;
	uint8_t shatype;
	uint8_t shamode;
	uint8_t cmdid;
	uint8_t hmacstart;
	uint8_t uniqueid;
};
#endif /* CFG_AMD_ASU_HMAC */

static struct asu_shadev *asu_shadev;

static const struct crypto_hash_ops asu_hash_ops;
static struct asu_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx);

#if defined(CFG_AMD_ASU_HMAC)
static const struct crypto_mac_ops asu_hmac_ops;
static struct asu_hmac_ctx *to_hmac_ctx(struct crypto_mac_ctx *ctx);
#endif /* CFG_AMD_ASU_HMAC */

/*
 * asu_shadev_acquire() - Claim a SHA engine slot by module ID.
 * @module: ASU_MODULE_SHA2_ID or ASU_MODULE_SHA3_ID
 *
 * Return: TEE_SUCCESS if the slot was free and is now claimed,
 *         TEE_ERROR_NOT_IMPLEMENTED if the slot is already in use.
 */
static TEE_Result asu_shadev_acquire(uint8_t module)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(&asu_shadev->engine_lock);
	if (module == ASU_MODULE_SHA2_ID && asu_shadev->sha2_available) {
		asu_shadev->sha2_available = false;
	} else if (module == ASU_MODULE_SHA3_ID && asu_shadev->sha3_available) {
		asu_shadev->sha3_available = false;
	} else {
		/* Engine busy; fallback to sw */
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}
	mutex_unlock(&asu_shadev->engine_lock);

	return ret;
}

/*
 * asu_shadev_release() - Release a previously claimed SHA engine slot.
 * @module: ASU_MODULE_SHA2_ID or ASU_MODULE_SHA3_ID
 */
static void asu_shadev_release(uint8_t module)
{
	mutex_lock(&asu_shadev->engine_lock);
	if (module == ASU_MODULE_SHA2_ID) {
		assert(!asu_shadev->sha2_available);
		asu_shadev->sha2_available = true;
	} else if (module == ASU_MODULE_SHA3_ID) {
		assert(!asu_shadev->sha3_available);
		asu_shadev->sha3_available = true;
	}
	mutex_unlock(&asu_shadev->engine_lock);
}

/* ---- SHA hash functions ---- */

/*
 * asu_hash_get_alg() - Get fw engine module ID and Hash mode.
 * @algo:	TEE algo type.
 * @module:	Engine module ID
 * @mode:	Hash operation mode
 * Map TEE algo type to fw module ID amd mode.
 *
 * Return: TEE_SUCCESS or TEE_ERROR_NOT_IMPLEMENTED
 */

static TEE_Result asu_hash_get_alg(uint32_t algo,
				   uint32_t *module,
				   uint32_t *mode)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (algo) {
	case TEE_ALG_SHA256:
		*module = ASU_MODULE_SHA2_ID;
		*mode = ASU_SHA_MODE_SHA256;
		break;
	case TEE_ALG_SHA384:
		*module = ASU_MODULE_SHA2_ID;
		*mode = ASU_SHA_MODE_SHA384;
		break;
	case TEE_ALG_SHA512:
		*module = ASU_MODULE_SHA2_ID;
		*mode = ASU_SHA_MODE_SHA512;
		break;
	case TEE_ALG_SHA3_256:
		*module = ASU_MODULE_SHA3_ID;
		*mode = ASU_SHA_MODE_SHA256;
		break;
	case TEE_ALG_SHA3_384:
		*module = ASU_MODULE_SHA3_ID;
		*mode = ASU_SHA_MODE_SHA384;
		break;
	case TEE_ALG_SHA3_512:
		*module = ASU_MODULE_SHA3_ID;
		*mode = ASU_SHA_MODE_SHA512;
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	return ret;
}

/*
 * asu_hash_initialize() - Initialize private asu_hash_ctx for hash operation.
 * @ctx: crypto context used by the crypto_hash_*() functions
 * Initialize hash operation request
 *
 * Return: TEE_SUCCESS or TEE_ERROR_BAD_PARAMETERS
 */

static TEE_Result asu_hash_initialize(struct crypto_hash_ctx *ctx)
{
	to_hash_ctx(ctx)->shastart = ASU_SHA_START;

	return TEE_SUCCESS;
}

/*
 * asu_sha_op() - Perform hash operation.
 * @asu_hashctx:Request private hash context
 * @op:		asu_sha_op_cmd parameters for fw engine
 * @module:	Engine module ID
 * @data:	Output digest received from engine
 * Create request header, send and wait for result
 * from engine.
 *
 * Return: TEE_SUCCESS or TEE_ERROR_GENERIC
 */

static TEE_Result asu_sha_op(struct asu_hash_ctx *asu_hashctx,
			     struct asu_sha_op_cmd *op,
			     uint8_t module)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t header = 0;
	uint32_t status = 0;

	header = asu_create_header(ASU_SHA_OPERATION_CMD_ID,
				   asu_hashctx->uniqueid, module,
				   sizeof(*op) / sizeof(uint32_t));
	ret = asu_update_queue_buffer_n_send_ipi(&asu_hashctx->cparam, op,
						 sizeof(*op), header,
						 &status);
	if (status) {
		EMSG("FW error 0x%x\n", status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

/*
 * asu_hash_update() - Send update request to engine.
 * @asu_hashctx:Request private hash context
 * @data:	Input data buffer
 * @len:	Size of data buffer
 * Send update request to engine
 * from engine.
 *
 * Return: TEE_SUCCESS or TEE_ERROR_GENERIC
 */

static TEE_Result asu_hash_update(struct asu_hash_ctx *asu_hashctx,
				  uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	struct asu_sha_op_cmd op = {};
	struct asu_client_params *cparam = NULL;
	uint32_t remaining = 0;

	/* Inputs of client request */
	cparam = &asu_hashctx->cparam;
	cparam->priority = ASU_PRIORITY_HIGH;
	cparam->cbhandler = NULL;

	/* Inputs of SHA request */
	cache_operation(TEE_CACHEFLUSH, data, len);
	op.hashaddr = 0;
	op.hashbufsize = 0;
	op.shamode = asu_hashctx->shamode;
	op.islast = 0;
	remaining = len;
	while (remaining) {
		op.datasize = MIN(remaining, ASU_DATA_CHUNK_LEN);
		op.opflags = ASU_SHA_UPDATE | asu_hashctx->shastart;
		op.dataaddr = virt_to_phys(data);
		remaining -= op.datasize;
		data += op.datasize;
		ret = asu_sha_op(asu_hashctx, &op, asu_hashctx->module);
		if (ret)
			break;
		asu_hashctx->shastart = 0;
	}

	return ret;
}

static TEE_Result asu_hash_do_update(struct crypto_hash_ctx *ctx,
				     const uint8_t *data, size_t len)
{
	struct asu_hash_ctx *asu_hashctx = NULL;

	if (!len) {
		DMSG("This is 0 len task, skip");
		return TEE_SUCCESS;
	}

	if (!data && len) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	asu_hashctx = to_hash_ctx(ctx);
	if (asu_hashctx->uniqueid == ASU_UNIQUE_ID_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	return asu_hash_update(asu_hashctx, (uint8_t *)data, len);
}

/*
 * asu_hash_final() - Send final request to engine.
 * @asu_hashctx:Request private hash context
 * @digest:	Output digest buffer
 * @len:	Size of digest buffer
 *
 * Send final request to engine and populate digest result
 *
 * Return: TEE_SUCCESS, TEE_ERROR_BAD_PARAMETERS or TEE_ERROR_GENERIC
 */

static TEE_Result asu_hash_final(struct asu_hash_ctx *asu_hashctx,
				 uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	struct asu_sha_op_cmd op = {};
	struct asu_client_params *cparam = NULL;
	uint8_t *dma_digest = NULL;

	if (!digest || len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	cparam = &asu_hashctx->cparam;
	cparam->priority = ASU_PRIORITY_HIGH;
	cparam->cbhandler = NULL;

	/* Inputs of SHA request */
	op.dataaddr = 0;
	op.datasize = 0;
	op.hashbufsize = len;
	if (asu_hashctx->shamode == ASU_SHA_MODE_SHA256)
		op.hashbufsize = ASU_SHA_256_HASH_LEN;
	else if (asu_hashctx->shamode == ASU_SHA_MODE_SHA384)
		op.hashbufsize = ASU_SHA_384_HASH_LEN;
	else if (asu_hashctx->shamode == ASU_SHA_MODE_SHA512)
		op.hashbufsize = ASU_SHA_512_HASH_LEN;

	dma_digest = memalign(ASU_DMA_ALIGNMENT, op.hashbufsize);
	if (!dma_digest) {
		EMSG("Failed to allocate DMA buffer for hash digest");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	op.shamode = asu_hashctx->shamode;
	op.islast = 1;
	op.opflags = ASU_SHA_FINISH | asu_hashctx->shastart;
	op.hashaddr = virt_to_phys(dma_digest);
	cache_operation(TEE_CACHEFLUSH, dma_digest, op.hashbufsize);
	ret = asu_sha_op(asu_hashctx, &op, asu_hashctx->module);
	if (ret) {
		EMSG("SHA final operation failed");
		goto out;
	}
	cache_operation(TEE_CACHEINVALIDATE, dma_digest, op.hashbufsize);
	memcpy(digest, dma_digest, op.hashbufsize);

out:
	free(dma_digest);
	return ret;
}

static TEE_Result asu_hash_do_final(struct crypto_hash_ctx *ctx,
				    uint8_t *digest, size_t len)
{
	struct asu_hash_ctx *asu_hashctx = NULL;

	asu_hashctx = to_hash_ctx(ctx);

	return asu_hash_final(asu_hashctx, digest, len);
}

/*
 * asu_hash_ctx_free() - Free Private context.
 * @crypto_hash_ctx: crypto context used by the crypto_hash_*() functions
 * Release crypto engine and free private context memory.
 *
 * Return: void
 */

static void asu_hash_ctx_free(struct crypto_hash_ctx *ctx)
{
	struct asu_hash_ctx *asu_hashctx = to_hash_ctx(ctx);

	asu_free_unique_id(asu_hashctx->uniqueid);
	asu_hashctx->uniqueid = ASU_UNIQUE_ID_MAX;
	asu_shadev_release(asu_hashctx->module);
	free(asu_hashctx);
}

static const struct crypto_hash_ops asu_hash_ops = {
	.init = asu_hash_initialize,
	.update = asu_hash_do_update,
	.final = asu_hash_do_final,
	.free_ctx = asu_hash_ctx_free,
	/*
	 * Current engine does not support partial state copy operation.
	 */
	.copy_state = NULL,
};

/*
 * Returns the reference to the driver context
 *
 * @ctx  API Context
 */
static struct asu_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &asu_hash_ops);

	return container_of(ctx, struct asu_hash_ctx, hash_ctx);
}

/*
 * asu_hash_ctx_allocate() - Allocate Private context.
 * @crypto_hash_ctx: crypto context used by the crypto_hash_*() functions
 * @algo:	TEE algo type.
 * Grab crypto engine and free private context memory.
 *
 * Return: TEE_SUCCESS, TEE_ERROR_BAD_PARAMETERS or TEE_ERROR_OUT_OF_MEMORY
 */

static TEE_Result asu_hash_ctx_allocate(struct crypto_hash_ctx **ctx,
					uint32_t algo)
{
	struct asu_hash_ctx *asu_hashctx = NULL;
	uint32_t module = 0;
	uint32_t shamode = 0;
	TEE_Result ret = TEE_SUCCESS;

	ret = asu_hash_get_alg(algo, &module, &shamode);
	if (ret)
		return ret;

	ret = asu_shadev_acquire(module);
	if (ret)
		return ret;

	asu_hashctx = calloc(1, sizeof(*asu_hashctx));
	if (!asu_hashctx) {
		EMSG("Fail to alloc hash");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_dev_mem;
	}

	asu_hashctx->module = module;
	asu_hashctx->shamode = shamode;
	asu_hashctx->uniqueid = asu_alloc_unique_id();

	if (asu_hashctx->uniqueid == ASU_UNIQUE_ID_MAX) {
		EMSG("Fail to get unique ID");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto free_dev_mem;
	}
	asu_hashctx->hash_ctx.ops = &asu_hash_ops;
	*ctx = &asu_hashctx->hash_ctx;

	return ret;

free_dev_mem:
	asu_shadev_release(module);
	free(asu_hashctx);

	return ret;
}

#if defined(CFG_AMD_ASU_HMAC)
/* ---- HMAC functions ---- */

/*
 * Returns the reference to the HMAC driver context.
 *
 * @ctx  API MAC context
 */
static struct asu_hmac_ctx *to_hmac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &asu_hmac_ops);

	return container_of(ctx, struct asu_hmac_ctx, mac_ctx);
}

/*
 * asu_hmac_get_alg() - Map TEE HMAC algo to ASU SHA type, mode and tag length.
 * @algo:    TEE algorithm identifier
 * @shatype: Output SHA family (SHA2=0x02, SHA3=0x03)
 * @shamode: Output SHA mode (0=256, 1=384, 2=512)
 * @cmdid:   Output command ID (0=SHA2, 1=SHA3)
 * @hmaclen: Output HMAC tag length in bytes
 *
 * Return: TEE_SUCCESS or TEE_ERROR_NOT_IMPLEMENTED
 */
static TEE_Result asu_hmac_get_alg(uint32_t algo, uint8_t *shatype,
				   uint8_t *shamode, uint8_t *cmdid,
				   uint32_t *hmaclen)
{
	switch (algo) {
	case TEE_ALG_HMAC_SHA256:
		*shatype = ASU_HMAC_SHA2_TYPE;
		*shamode = ASU_SHA_MODE_SHA256;
		*cmdid = ASU_HMAC_CMD_SHA2;
		*hmaclen = ASU_SHA_256_HASH_LEN;
		break;
	case TEE_ALG_HMAC_SHA384:
		*shatype = ASU_HMAC_SHA2_TYPE;
		*shamode = ASU_SHA_MODE_SHA384;
		*cmdid = ASU_HMAC_CMD_SHA2;
		*hmaclen = ASU_SHA_384_HASH_LEN;
		break;
	case TEE_ALG_HMAC_SHA512:
		*shatype = ASU_HMAC_SHA2_TYPE;
		*shamode = ASU_SHA_MODE_SHA512;
		*cmdid = ASU_HMAC_CMD_SHA2;
		*hmaclen = ASU_SHA_512_HASH_LEN;
		break;
	case TEE_ALG_HMAC_SHA3_256:
		*shatype = ASU_HMAC_SHA3_TYPE;
		*shamode = ASU_SHA_MODE_SHA256;
		*cmdid = ASU_HMAC_CMD_SHA3;
		*hmaclen = ASU_SHA_256_HASH_LEN;
		break;
	case TEE_ALG_HMAC_SHA3_384:
		*shatype = ASU_HMAC_SHA3_TYPE;
		*shamode = ASU_SHA_MODE_SHA384;
		*cmdid = ASU_HMAC_CMD_SHA3;
		*hmaclen = ASU_SHA_384_HASH_LEN;
		break;
	case TEE_ALG_HMAC_SHA3_512:
		*shatype = ASU_HMAC_SHA3_TYPE;
		*shamode = ASU_SHA_MODE_SHA512;
		*cmdid = ASU_HMAC_CMD_SHA3;
		*hmaclen = ASU_SHA_512_HASH_LEN;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;
}

/*
 * asu_hmac_send_cmd() - Write HMAC command to ASU queue and ring IPI doorbell.
 * @hmac_ctx: Private HMAC context
 * @op:       Populated command payload
 *
 * Return: TEE_SUCCESS or TEE_ERROR_GENERIC
 */
static TEE_Result asu_hmac_send_cmd(struct asu_hmac_ctx *hmac_ctx,
				    struct asu_hmac_op_cmd *op)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t header = 0;
	uint32_t status = 0;

	header = asu_create_header(hmac_ctx->cmdid, hmac_ctx->uniqueid,
				   ASU_MODULE_HMAC_ID,
				   sizeof(*op) / sizeof(uint32_t));
	ret = asu_update_queue_buffer_n_send_ipi(&hmac_ctx->cparam, op,
						 sizeof(*op), header, &status);
	if (status) {
		EMSG("ASUFW HMAC error 0x%x", status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

/*
 * asu_hmac_do_init() - Save HMAC key into DMA buffer; arm first-update flag.
 * @ctx:     Crypto MAC context
 * @key:     HMAC key bytes
 * @key_len: Key length in bytes
 *
 * No IPI is sent here. The INIT IPI is folded into the first update call
 * so both key and first data chunk are delivered to ASUFW together.
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_hmac_do_init(struct crypto_mac_ctx *ctx,
				   const uint8_t *key, size_t key_len)
{
	struct asu_hmac_ctx *hmac_ctx = to_hmac_ctx(ctx);
	size_t cacheline_len = dcache_get_line_size();
	size_t alloc_len = ROUNDUP(key_len, cacheline_len);

	if (!key || !key_len || key_len > ASU_HMAC_MAX_KEY_LEN) {
		EMSG("Invalid HMAC key");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (hmac_ctx->key_buf) {
		free_wipe(hmac_ctx->key_buf);
		hmac_ctx->key_buf = NULL;
	}

	hmac_ctx->key_buf = memalign(cacheline_len, alloc_len);
	if (!hmac_ctx->key_buf) {
		EMSG("Failed to allocate HMAC key DMA buffer");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memset(hmac_ctx->key_buf, 0, alloc_len);
	memcpy(hmac_ctx->key_buf, key, key_len);
	hmac_ctx->key_len = key_len;
	cache_operation(TEE_CACHEFLUSH, hmac_ctx->key_buf, alloc_len);

	hmac_ctx->hmacstart = ASU_HMAC_OP_INIT;

	return TEE_SUCCESS;
}

/*
 * asu_hmac_do_update() - Feed message data to ASUFW in 4 KB chunks.
 * @ctx:  Crypto MAC context
 * @data: Input message buffer
 * @len:  Length in bytes
 *
 * First IPI sets opflags = INIT|UPDATE and carries the key. Subsequent
 * IPIs set opflags = UPDATE only.
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_hmac_do_update(struct crypto_mac_ctx *ctx,
				     const uint8_t *data, size_t len)
{
	struct asu_hmac_ctx *hmac_ctx = to_hmac_ctx(ctx);
	size_t cacheline_len = dcache_get_line_size();
	struct asu_hmac_op_cmd op = {};
	TEE_Result ret = TEE_SUCCESS;
	uint8_t *dma_buf = NULL;
	uint32_t remaining = 0;

	if (!len) {
		DMSG("Zero-length HMAC update, skipping");
		return TEE_SUCCESS;
	}

	if (!data) {
		DMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (hmac_ctx->uniqueid >= ASU_UNIQUE_ID_MAX)
		return TEE_ERROR_BAD_STATE;

	op.shatype = hmac_ctx->shatype;
	op.shamode = hmac_ctx->shamode;
	op.hmaclen = hmac_ctx->hmaclen;
	op.keyinaddr = virt_to_phys(hmac_ctx->key_buf);
	op.keyinlen = hmac_ctx->key_len;
	remaining = len;

	dma_buf = memalign(cacheline_len, ASU_DATA_CHUNK_LEN);
	if (!dma_buf) {
		EMSG("Failed to allocate HMAC data DMA buffer");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	op.msgaddr = virt_to_phys(dma_buf);

	if (!hmac_ctx->hmacstart) {
		op.keyinaddr = 0;
		op.keyinlen = 0;
	}

	while (remaining) {
		op.msglen = MIN(remaining, ASU_DATA_CHUNK_LEN);
		op.opflags = hmac_ctx->hmacstart | ASU_HMAC_OP_UPDATE;

		memcpy(dma_buf, data, op.msglen);
		cache_operation(TEE_CACHEFLUSH, dma_buf,
				ROUNDUP(op.msglen, cacheline_len));

		ret = asu_hmac_send_cmd(hmac_ctx, &op);
		if (ret)
			break;

		hmac_ctx->hmacstart = 0;
		data += op.msglen;
		remaining -= op.msglen;
	}

	free(dma_buf);

	return ret;
}

/*
 * asu_hmac_result_cb() - Copy HMAC tag from the IPI response buffer.
 * @cbptr: Pointer to struct asu_hmac_result.
 * @resp:  ASU response buffer (valid only for the duration of this call).
 *
 * ASUFW writes the tag to resp.arg[1] (status is at resp.arg[0]).
 *
 * Return: TEE_SUCCESS
 */
static TEE_Result asu_hmac_result_cb(void *cbptr, struct asu_resp_buf *resp)
{
	struct asu_hmac_result *res = cbptr;

	memcpy(res->buf, &resp->arg[1], res->len);
	return TEE_SUCCESS;
}

/*
 * asu_hmac_do_final() - Send FINISH IPI and return the HMAC tag.
 * @ctx:    Crypto MAC context
 * @digest: Output buffer for HMAC tag
 * @len:    Size of @digest in bytes
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_hmac_do_final(struct crypto_mac_ctx *ctx,
				    uint8_t *digest, size_t len)
{
	struct asu_hmac_ctx *hmac_ctx = to_hmac_ctx(ctx);
	struct asu_hmac_op_cmd op = {};
	TEE_Result ret = TEE_SUCCESS;

	if (!digest || !len || len > hmac_ctx->hmaclen) {
		EMSG("Invalid HMAC output parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hmac_ctx->result.len = hmac_ctx->hmaclen;

	op.hmaclen = hmac_ctx->hmaclen;
	op.shatype = hmac_ctx->shatype;
	op.shamode = hmac_ctx->shamode;
	op.islast = 1;
	op.opflags = ASU_HMAC_OP_FINISH;

	hmac_ctx->cparam.cbhandler = asu_hmac_result_cb;
	hmac_ctx->cparam.cbptr = &hmac_ctx->result;

	ret = asu_hmac_send_cmd(hmac_ctx, &op);
	hmac_ctx->cparam.cbhandler = NULL;
	hmac_ctx->cparam.cbptr = NULL;

	if (ret) {
		EMSG("HMAC FINISH IPI failed");
		return ret;
	}

	memcpy(digest, hmac_ctx->result.buf, len);

	return ret;
}

/*
 * asu_hmac_do_free_ctx() - Zeroize key and release private context.
 * @ctx: Crypto MAC context
 */
static void asu_hmac_do_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct asu_hmac_ctx *hmac_ctx = to_hmac_ctx(ctx);
	uint8_t sha_module = (hmac_ctx->cmdid == ASU_HMAC_CMD_SHA2) ?
			     ASU_MODULE_SHA2_ID : ASU_MODULE_SHA3_ID;

	if (hmac_ctx->key_buf) {
		free_wipe(hmac_ctx->key_buf);
		hmac_ctx->key_buf = NULL;
	}

	asu_free_unique_id(hmac_ctx->uniqueid);
	hmac_ctx->uniqueid = ASU_UNIQUE_ID_MAX;
	asu_shadev_release(sha_module);
	free(hmac_ctx);
}

static const struct crypto_mac_ops asu_hmac_ops = {
	.init = asu_hmac_do_init,
	.update = asu_hmac_do_update,
	.final = asu_hmac_do_final,
	.free_ctx = asu_hmac_do_free_ctx,
	/*
	 * ASUFW does not expose partial inner-hash state.
	 */
	.copy_state = NULL,
};

/*
 * asu_hmac_ctx_allocate() - Allocate private HMAC context.
 * @ctx:  Output crypto MAC context
 * @algo: TEE HMAC algorithm identifier
 *
 * Acquires the shared SHA engine slot from asu_shadev so that HMAC and
 * hash operations are serialised on the same underlying hardware.
 *
 * Return: TEE_SUCCESS or error code
 */
static TEE_Result asu_hmac_ctx_allocate(struct crypto_mac_ctx **ctx,
					uint32_t algo)
{
	struct asu_hmac_ctx *hmac_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint8_t sha_module = 0;
	uint32_t hmaclen = 0;
	uint8_t shatype = 0;
	uint8_t shamode = 0;
	uint8_t cmdid = 0;

	ret = asu_hmac_get_alg(algo, &shatype, &shamode, &cmdid, &hmaclen);
	if (ret) {
		DMSG("Unsupported HMAC algo 0x%08" PRIx32, algo);
		return ret;
	}

	sha_module = (cmdid == ASU_HMAC_CMD_SHA2) ? ASU_MODULE_SHA2_ID :
						    ASU_MODULE_SHA3_ID;
	ret = asu_shadev_acquire(sha_module);
	if (ret)
		return ret;

	hmac_ctx = calloc(1, sizeof(*hmac_ctx));
	if (!hmac_ctx) {
		EMSG("Failed to allocate HMAC context");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err_release_engine;
	}

	hmac_ctx->shatype = shatype;
	hmac_ctx->shamode = shamode;
	hmac_ctx->cmdid = cmdid;
	hmac_ctx->hmaclen = hmaclen;
	hmac_ctx->cparam.priority = ASU_PRIORITY_HIGH;
	hmac_ctx->uniqueid = asu_alloc_unique_id();

	if (hmac_ctx->uniqueid >= ASU_UNIQUE_ID_MAX) {
		EMSG("No ASU unique IDs available");
		ret = TEE_ERROR_BUSY;
		goto err_free_ctx;
	}

	hmac_ctx->mac_ctx.ops = &asu_hmac_ops;
	*ctx = &hmac_ctx->mac_ctx;
	return TEE_SUCCESS;

err_free_ctx:
	free(hmac_ctx);

err_release_engine:
	asu_shadev_release(sha_module);

	return ret;
}

#endif /* CFG_AMD_ASU_HMAC */

static TEE_Result asu_hash_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	asu_shadev = calloc(1, sizeof(*asu_shadev));
	mutex_init(&asu_shadev->engine_lock);
	asu_shadev->sha2_available = true;
	asu_shadev->sha3_available = true;

	ret = drvcrypt_register_hash(&asu_hash_ctx_allocate);
	if (ret)
		EMSG("ASU hash register to crypto fail ret=%#"PRIx32, ret);

#if defined(CFG_AMD_ASU_HMAC)
	ret = drvcrypt_register_hmac(asu_hmac_ctx_allocate);
	if (ret)
		EMSG("ASU HMAC register failed ret=%#"PRIx32, ret);
#endif

	return ret;
}
driver_init(asu_hash_init);
