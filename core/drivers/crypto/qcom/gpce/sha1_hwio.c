// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * Implementation of GPCE hash initialization.
 */

#include <stdlib.h>
#include <string.h>

#include "ce_hal.h"
#include "hash.h"

static TEE_Result SHA1_HWIO_iv_init(struct hash_ctx_s *me)
{
	struct ce_sha_ctx_s *c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
	TEE_Result ret = TEE_SUCCESS;

	ret = CE_HAL_set_auth_iv(c->ce_ctx, 0, INIT_DATA_CE_SHA1_h0);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 1, INIT_DATA_CE_SHA1_h1);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 2, INIT_DATA_CE_SHA1_h2);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 3, INIT_DATA_CE_SHA1_h3);
	if (ret != TEE_SUCCESS)
		return ret;
	ret = CE_HAL_set_auth_iv(c->ce_ctx, 4, INIT_DATA_CE_SHA1_h4);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}

static TEE_Result SHA1_CE_HWIO_INIT(struct hash_ctx_s *me)
{
	struct ce_sha_ctx_s *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = SHA_CMN_CE_init(me);
	if (ret != TEE_SUCCESS)
		goto out;
	c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
	c->iblk_h = util_blk_buf_new();
	if (!c->iblk_h) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	ret = util_blk_buf_init(c->iblk_h, CE_MAX_BLOCK_SIZE,
				SHA_CMN_HWIO_process_din,
				(void *)me);
	if (ret != TEE_SUCCESS)
		goto out;

	c->ce_ctx = CE_HAL_new();
	if (!c->ce_ctx) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	ret = CE_HAL_init(c->ce_ctx, true);
	if (ret != TEE_SUCCESS)
		goto out;
	ret = SHA1_HWIO_iv_init(me);
out:
	return ret;
}

TEE_Result SHA1_CE_HWIO_init(struct hash_ctx_s *me)
{
	struct ce_sha_ctx_s *c = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(me))
		return TEE_ERROR_BAD_STATE;
	me->md_sz = SHA1_DIGEST_SIZE;
	if (HASH_IS_CTX_NULL(me) || !me->ctx ||
	    me->ctx_sz != sizeof(struct ce_sha_ctx_s)) {
		me->ctx = calloc(1, sizeof(struct ce_sha_ctx_s));
		if (!me->ctx)
			return TEE_ERROR_OUT_OF_MEMORY;
		me->ctx_sz = sizeof(struct ce_sha_ctx_s);
	} else {
		c = HASH_GET_DIGEST_CTX(me, struct ce_sha_ctx_s);
		if (c->iblk_h) {
			ret = util_blk_buf_free(c->iblk_h);
			if (ret != TEE_SUCCESS)
				return ret;
		}
		if (c->ce_ctx) {
			ret = CE_HAL_free(c->ce_ctx);
			if (ret != TEE_SUCCESS)
				return ret;
		}
		memset(me->ctx, 0, sizeof(struct ce_sha_ctx_s));
	}

	ret = SHA1_CE_HWIO_INIT(me);
	if (ret != TEE_SUCCESS)
		return ret;

	return TEE_SUCCESS;
}
