// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Scatter-Gatter Table management utilities.
 */
#include <caam_common.h>
#include <caam_utils_sgt.h>
#include <tee/cache.h>

/*
 * Cache operation on SGT table
 *
 * @op     Cache operation
 * @insgt  SGT table
 */
void caam_cache_op_sgt(enum utee_cache_operation op, struct caamsgtbuf *insgt)
{
	uint8_t idx;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			(insgt->number * sizeof(struct caamsgt)));
	for (idx = 0; idx < insgt->number; idx++) {
		/* If buffer is not cacheable, do nothing */
		if (insgt->buf[idx].nocache == 0)
			cache_operation(op, (void *)(insgt->buf[idx].data),
					insgt->buf[idx].length);
	}
}
