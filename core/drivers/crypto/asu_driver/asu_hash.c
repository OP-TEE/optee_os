// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/amd/asu_client.h>
#include <drvcrypt_hash.h>
#include <initcall.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/unwind.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <tee/cache.h>
#include <trace.h>
#include <util.h>

#define ASU_SHA_OPERATION_CMD_ID		(0U)
/* SHA modes */
#define ASU_SHA_MODE_SHA256			(0U)
#define ASU_SHA_MODE_SHA384			(1U)
#define ASU_SHA_MODE_SHA512			(2U)
#define ASU_SHA_MODE_SHAKE256			(4U)

/* SHA operation mode */
#define ASU_SHA_START				(0x1U)
#define ASU_SHA_UPDATE				(0x2U)
#define ASU_SHA_FINISH				(0x4U)

/* SHA hash lengths */
#define ASU_SHA_256_HASH_LEN			(32U)
#define ASU_SHA_384_HASH_LEN			(48U)
#define ASU_SHA_512_HASH_LEN			(64U)
#define ASU_SHAKE_256_HASH_LEN			(32U)
#define ASU_SHAKE_256_MAX_HASH_LEN		(136U)
#define ASU_DATA_CHUNK_LEN			(4096U)

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

struct asu_hash_cbctx {
	uint8_t *digest;
	size_t len;
};

static struct crypto_hash_ops asu_hash_ops;
static struct asu_shadev *asu_shadev;
static struct asu_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx);

/**
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

/**
 * asu_hash_initialize() - Initialize private asu_hash_ctx for hash operation.
 * @ctx: crypto context used by the crypto_hash_*() functions
 * Initialize hash operation request
 *
 * Return: TEE_SUCCESS or TEE_ERROR_BAD_PARAMETERS
 */

static TEE_Result asu_hash_initialize(struct crypto_hash_ctx *ctx)
{
	struct asu_hash_ctx *asu_hashctx = NULL;

	if (!ctx) {
		EMSG("Input ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	asu_hashctx = to_hash_ctx(ctx);
	asu_hashctx->shastart = ASU_SHA_START;

	return TEE_SUCCESS;
}

/**
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
	uint32_t header;
	int status;

	header = asu_create_header(ASU_SHA_OPERATION_CMD_ID,
				   asu_hashctx->uniqueid, module, 0U);
	ret = asu_update_queue_buffer_n_send_ipi(&asu_hashctx->cparam, op,
						 sizeof(*op), header,
						 &status);
	if (status) {
		EMSG("FW error 0x%x\n", status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

/**
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
	uint32_t remaining;

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

	if (!ctx || (!data && len)) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	asu_hashctx = to_hash_ctx(ctx);
	if (asu_hashctx->uniqueid == ASU_UNIQUE_ID_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	return asu_hash_update(asu_hashctx, (uint8_t *)data, len);
}

static TEE_Result asu_hash_cb(void *cbrefptr, struct asu_resp_buf *resp_buf)
{
	struct asu_hash_cbctx *cbctx;
	uint8_t *src_addr;

	cbctx = cbrefptr;
	src_addr = (uint8_t *)&resp_buf->arg[ASU_RESPONSE_BUFF_ADDR_INDEX];
	memcpy(cbctx->digest, src_addr, cbctx->len);

	return TEE_SUCCESS;
}

/**
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
	struct asu_hash_cbctx cbctx = {};

	if (!digest || len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	cbctx.digest = digest;
	cbctx.len = len;
	cparam = &asu_hashctx->cparam;
	cparam->priority = ASU_PRIORITY_HIGH;
	cparam->cbptr = &cbctx;
	cparam->cbhandler = asu_hash_cb;

	/* Inputs of SHA request */
	op.dataaddr = 0;
	op.datasize = 0;
	op.hashaddr = virt_to_phys((void *)digest);
	op.hashbufsize = len;
	if (asu_hashctx->shamode == ASU_SHA_MODE_SHA256)
		op.hashbufsize = ASU_SHA_256_HASH_LEN;
	else if (asu_hashctx->shamode == ASU_SHA_MODE_SHA384)
		op.hashbufsize = ASU_SHA_384_HASH_LEN;
	else if (asu_hashctx->shamode == ASU_SHA_MODE_SHA512)
		op.hashbufsize = ASU_SHA_512_HASH_LEN;

	op.shamode = asu_hashctx->shamode;
	op.islast = 1;
	op.opflags = ASU_SHA_FINISH | asu_hashctx->shastart;
	ret = asu_sha_op(asu_hashctx, &op, asu_hashctx->module);
	cache_operation(TEE_CACHEFLUSH, digest, op.hashbufsize);

	return ret;
}

static TEE_Result asu_hash_do_final(struct crypto_hash_ctx *ctx,
				    uint8_t *digest, size_t len)
{
	struct asu_hash_ctx *asu_hashctx = NULL;

	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;
	asu_hashctx = to_hash_ctx(ctx);

	return asu_hash_final(asu_hashctx, digest, len);
}

/**
 * asu_hash_ctx_free() - Free Private context.
 * @crypto_hash_ctx: crypto context used by the crypto_hash_*() functions
 * Release crypto engine and free private context memory.
 *
 * Return: void
 */

static void asu_hash_ctx_free(struct crypto_hash_ctx *ctx)
{
	struct asu_hash_ctx *asu_hashctx = NULL;

	if (!ctx)
		return;
	asu_hashctx = to_hash_ctx(ctx);
	asu_free_unique_id(asu_hashctx->uniqueid);
	asu_hashctx->uniqueid = ASU_UNIQUE_ID_MAX;
	mutex_lock(&asu_shadev->engine_lock);
	if (asu_hashctx->module == ASU_MODULE_SHA2_ID &&
	    !asu_shadev->sha2_available)
		asu_shadev->sha2_available = 1;
	else if (asu_hashctx->module == ASU_MODULE_SHA3_ID &&
		 !asu_shadev->sha3_available)
		asu_shadev->sha3_available = 1;
	mutex_unlock(&asu_shadev->engine_lock);
	asu_hashctx = to_hash_ctx(ctx);
	free(asu_hashctx);
}

static struct crypto_hash_ops asu_hash_ops = {
	.init = asu_hash_initialize,
	.update = asu_hash_do_update,
	.final = asu_hash_do_final,
	.free_ctx = asu_hash_ctx_free,
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

/**
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
	uint32_t module;
	uint32_t shamode;
	TEE_Result ret = TEE_SUCCESS;

	if (!ctx) {
		EMSG("ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = asu_hash_get_alg(algo, &module, &shamode);
	if (ret)
		return ret;
	mutex_lock(&asu_shadev->engine_lock);
	if (module == ASU_MODULE_SHA2_ID && asu_shadev->sha2_available) {
		asu_shadev->sha2_available = 0;
	} else if (module == ASU_MODULE_SHA3_ID && asu_shadev->sha3_available) {
		asu_shadev->sha3_available = 0;
	} else {
		mutex_unlock(&asu_shadev->engine_lock);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	mutex_unlock(&asu_shadev->engine_lock);

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
	mutex_lock(&asu_shadev->engine_lock);
	if (asu_hashctx->module == ASU_MODULE_SHA2_ID &&
	    !asu_shadev->sha2_available)
		asu_shadev->sha2_available = 1;
	else if (asu_hashctx->module == ASU_MODULE_SHA3_ID &&
		 !asu_shadev->sha3_available)
		asu_shadev->sha3_available = 1;
	mutex_unlock(&asu_shadev->engine_lock);

	if (asu_hashctx)
		free(asu_hashctx);

	return ret;
}

static TEE_Result asu_hash_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	asu_shadev = calloc(1, sizeof(*asu_shadev));
	mutex_init(&asu_shadev->engine_lock);
	asu_shadev->sha2_available = 1;
	asu_shadev->sha3_available = 1;
	ret = drvcrypt_register_hash(&asu_hash_ctx_allocate);
	if (ret)
		EMSG("ASU hash register to crypto fail ret=%#"PRIx32, ret);

	return ret;
}
driver_init(asu_hash_init);
