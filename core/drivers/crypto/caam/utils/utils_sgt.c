// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    utils_sgt.c
 *
 * @brief   Scatter-Gatter Table management utilities.\n
 */

/* Global includes */
#include <tee_api_types.h>
#include <tee/cache.h>
#include <utee_defines.h>

/* Local includes */
#include "caam_common.h"

/* Utils includes */
#include "utils_sgt.h"

/**
 * @brief   Cache operation on SGT table
 *
 * @param[in] op     Cache operation
 * @param[in] insgt  SGT table
 */
void caam_cache_op_sgt(enum utee_cache_operation op, struct sgtbuf *insgt)
{
	uint8_t idx;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			(insgt->number * sizeof(struct sgt)));
	for (idx = 0; idx < insgt->number; idx++) {
		/* If buffer is not cacheable, do nothing */
		if (insgt->buf[idx].nocache == 0)
			cache_operation(op, (void *)(insgt->buf[idx].data),
					insgt->buf[idx].length);
	}
}

