// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/refcount.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <string.h>

#include "ipi.h"

/* single engine */
struct mutex lock = MUTEX_INITIALIZER;

#define FIRST_PACKET	BIT(30)
#define NEXT_PACKET	BIT(31)

enum versal_sha3_state {
	SHA3_STNDBY = 0, SHA3_INIT, SHA3_RUN
};

struct update_request {
	uint8_t *data;
	size_t len;
	/* checkpatch requires this empty line */
	STAILQ_ENTRY(update_request) link;
};

struct versal_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	enum versal_sha3_state state;
	/* checkpatch requires this empty line */
	STAILQ_HEAD(update_request_list, update_request) req_list;
};

static const struct crypto_hash_ops versal_ops;

static struct versal_hash_ctx *to_versal_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &versal_ops);

	return container_of(ctx, struct versal_hash_ctx, hash_ctx);
}

static TEE_Result do_hash_init(struct crypto_hash_ctx *ctx)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);

	if (c->state != SHA3_STNDBY)
		return TEE_ERROR_GENERIC;

	c->state = SHA3_INIT;

	return TEE_SUCCESS;
}

static TEE_Result do_hash_update(struct crypto_hash_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);
	struct update_request *req = NULL;

	/*
	 * The engine does not have the concept of context, so all update
	 * requests will be queued and processed at the final stage
	 */
	req = malloc(sizeof(*req));
	if (!req)
		return TEE_ERROR_OUT_OF_MEMORY;

	req->data = malloc(len);
	if (!req->data) {
		free(req);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	req->len = len;
	memcpy(req->data, data, req->len);
	STAILQ_INSERT_TAIL(&c->req_list, req, link);

	return TEE_SUCCESS;
}

static TEE_Result hash_update(struct crypto_hash_ctx *ctx,
			      const uint8_t *data, size_t len)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);
	TEE_Result ret = TEE_SUCCESS;
	struct versal_mbox_mem p = { };
	struct cmd_args arg = { };
	uint32_t init_mask = 0;
	uint32_t err = 0;

	if (c->state == SHA3_INIT)
		init_mask = FIRST_PACKET;

	versal_mbox_alloc(len, data, &p);

	arg.ibuf[0].mem = p;
	arg.data[0] = NEXT_PACKET | init_mask | len;
	arg.dlen = 1;

	if (versal_crypto_request(SHA3_UPDATE, &arg, &err))
		ret = TEE_ERROR_GENERIC;
	else
		c->state = SHA3_RUN;

	free(p.buf);

	return ret;
}

static TEE_Result do_hash_final(struct crypto_hash_ctx *ctx,
				uint8_t *digest, size_t len)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);
	struct update_request *req = NULL;
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	uint32_t err = 0;

	if (c->state == SHA3_STNDBY)
		return TEE_ERROR_GENERIC;

	/* Book the engine */
	mutex_lock(&lock);
	STAILQ_FOREACH(req, &c->req_list, link) {
		if (hash_update(ctx, req->data, req->len)) {
			/* Release the engine */
			mutex_unlock(&lock);
			return TEE_ERROR_GENERIC;
		}

		STAILQ_REMOVE(&c->req_list, req, update_request, link);
		free(req->data);
		free(req);
	}

	versal_mbox_alloc(len, NULL, &p);
	arg.ibuf[0].mem = p;

	if (versal_crypto_request(SHA3_UPDATE, &arg, &err))
		ret = TEE_ERROR_GENERIC;
	else
		c->state = SHA3_STNDBY;

	/* Release the engine*/
	mutex_unlock(&lock);

	memcpy(digest, p.buf, p.len);
	free(p.buf);

	return ret;
}

static void do_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
			       struct crypto_hash_ctx *src_ctx)
{
	struct versal_hash_ctx *src_hctx = NULL;
	struct versal_hash_ctx *dst_hctx = NULL;
	struct update_request *src_req = NULL;
	struct update_request *dst_req = NULL;

	src_hctx = container_of(src_ctx, struct versal_hash_ctx, hash_ctx);
	dst_hctx = container_of(dst_ctx, struct versal_hash_ctx, hash_ctx);

	dst_hctx->hash_ctx = src_hctx->hash_ctx;
	dst_hctx->state = src_hctx->state;

	/* duplicate the queue requests */
	STAILQ_FOREACH(src_req, &src_hctx->req_list, link) {
		dst_req = malloc(sizeof(*dst_req));
		if (!dst_req)
			panic();
		dst_req->len = src_req->len;

		dst_req->data = malloc(dst_req->len);
		if (!dst_req->data)
			panic();

		memcpy(dst_req->data, src_req->data, dst_req->len);
		STAILQ_INSERT_TAIL(&dst_hctx->req_list, dst_req, link);
	}
}

static void do_hash_free(struct crypto_hash_ctx *ctx)
{
	struct versal_hash_ctx *hctx = NULL;
	struct update_request *req = NULL;

	hctx = container_of(ctx, struct versal_hash_ctx, hash_ctx);

	/* Requests were pushed but never finalized */
	STAILQ_FOREACH(req, &hctx->req_list, link) {
		free(req->data);
		free(req);
	}
	free(hctx);
}

static TEE_Result versal_hash_alloc(struct crypto_hash_ctx **ctx,
				    uint32_t algo __unused)
{
	struct versal_hash_ctx *vctx = NULL;

	if (algo != TEE_ALG_SHA3_384)
		return TEE_ERROR_NOT_IMPLEMENTED;

	vctx = calloc(1, sizeof(*vctx));
	if (!vctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	STAILQ_INIT(&vctx->req_list);
	vctx->hash_ctx.ops = &versal_ops;
	*ctx = &vctx->hash_ctx;

	return TEE_SUCCESS;
}

static const struct crypto_hash_ops versal_ops = {
	.copy_state = do_hash_copy_state,
	.free_ctx = do_hash_free,
	.update = do_hash_update,
	.final = do_hash_final,
	.init = do_hash_init,
};

static TEE_Result sha3_init(void)
{
	struct cmd_args arg = { };

	if (versal_crypto_request(SHA3_KAT, &arg, NULL))
		panic();

	return drvcrypt_register_hash(versal_hash_alloc);
}

/* Has to init early to provide the HUK */
service_init(sha3_init);
