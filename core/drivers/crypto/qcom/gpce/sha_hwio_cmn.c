// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * Implementation of GPCE HWIO hash transfers.
 */

#include <kernel/mutex.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include "hash.h"
#include "ce_hwio.h"

TEE_Result SHA_CMN_HWIO_process_din(void *ctx, const uint8_t *buf,
				    size_t buf_sz, bool first,
				    bool last)
{
	struct hash_ctx_s *me = (struct hash_ctx_s *)ctx;
	TEE_Result ret = TEE_ERROR_BAD_STATE;
	size_t seg_sz = 0;

	if (HASH_IS_CTX_NULL(me))
		return TEE_ERROR_BAD_STATE;
	if (!me->dev)
		return TEE_ERROR_BAD_STATE;
	mutex_lock(&me->dev->mutex);

	/* Set CE Context */
	if (HASH_IS_CTX_NULL(me) || !me->ctx ||
	    me->ctx_sz != sizeof(struct ce_sha_ctx_s))
		goto out;

	seg_sz = ROUNDUP(buf_sz, CE_HW_BLOCK_SIZE);
	ret = CE_HWIO_set_ce_ctx(me, buf_sz, seg_sz, first, last);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Transfer data to CE */
	ret = CE_HWIO_xfer_data(me, buf, seg_sz);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Get CE Context */
	ret = CE_HWIO_get_ce_ctx(me);

out:
	mutex_unlock(&me->dev->mutex);
	return ret;
}
