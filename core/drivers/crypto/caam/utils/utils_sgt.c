// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Scatter-Gatter Table management utilities.
 */
#include <caam_common.h>
#include <caam_utils_sgt.h>
#include <tee/cache.h>

void caam_cache_op_sgt(enum utee_cache_operation op, struct caamsgtbuf *insgt)
{
	unsigned int idx = 0;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			insgt->number * sizeof(struct caamsgt));
	for (idx = 0; idx < insgt->number; idx++) {
		if (!insgt->buf[idx].nocache)
			cache_operation(op, (void *)(insgt->buf[idx].data),
					insgt->buf[idx].length);
	}
}
