/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <compiler.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/static_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>

#define TA_NAME		"stats.ta"

#define STATS_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define STATS_CMD_PAGER_STATS		0
#define STATS_CMD_ALLOC_STATS		1

#define STATS_NB_POOLS			3

static TEE_Result get_alloc_stats(uint32_t type, TEE_Param p[4])
{
	struct tee_mm_pool_stats *stats;
	uint32_t size_to_retrieve;
	uint32_t pool_id;
	uint32_t i;

	/*
	 * p[0].value.a = pool id (from 0 to n)
	 *   - 0 means all the pools to be retrieved
	 *   - 1..n means pool id
	 * p[0].value.b = 0 if no reset of the stats
	 * p[1].memref.buffer = output buffer to struct tee_mm_pool_stats
	 */
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != type) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pool_id = p[0].value.a;
	if (pool_id > STATS_NB_POOLS)
		return TEE_ERROR_BAD_PARAMETERS;

	size_to_retrieve = sizeof(struct tee_mm_pool_stats);
	if (!pool_id)
		size_to_retrieve *= STATS_NB_POOLS;

	if (p[1].memref.size < size_to_retrieve) {
		p[1].memref.size = size_to_retrieve;
		return TEE_ERROR_SHORT_BUFFER;
	}
	p[1].memref.size = size_to_retrieve;
	stats = (struct tee_mm_pool_stats *)p[1].memref.buffer;

	for (i = 1; i <= STATS_NB_POOLS; i++) {
		if ((pool_id) && (i != pool_id))
			continue;

		switch (i) {
		case 1:
			strlcpy(stats->desc, "Heap", sizeof(stats->desc));
			stats->allocated = malloc_get_allocated();
			stats->max_allocated = malloc_get_max_allocated();
			stats->size = malloc_get_heap_size();
			if (p[0].value.b)
				malloc_reset_max_allocated();
			break;

		case 2:
			strlcpy(stats->desc, "Public DDR", sizeof(stats->desc));
			tee_mm_get_pool_stats(&tee_mm_pub_ddr, stats,
					      !!p[0].value.b);
			break;

		case 3:
			strlcpy(stats->desc, "Secure DDR", sizeof(stats->desc));
			tee_mm_get_pool_stats(&tee_mm_sec_ddr, stats,
					      !!p[0].value.b);
			break;

		default:
			EMSG("Wrong pool id");
			break;
		}

		stats++;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_pager_stats(uint32_t type, TEE_Param p[4])
{
	struct tee_pager_stats stats;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_NONE) != type) {
		EMSG("expect 3 output values as argument");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_pager_get_stats(&stats);
	p[0].value.a = stats.npages;
	p[0].value.b = stats.npages_all;
	p[1].value.a = stats.ro_hits;
	p[1].value.b = stats.rw_hits;
	p[2].value.a = stats.hidden_hits;
	p[2].value.b = stats.zi_released;

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
}

static TEE_Result open_session(uint32_t ptype __unused,
			       TEE_Param params[4] __unused,
			       void **ppsess __unused)
{
	return TEE_SUCCESS;
}

static void close_session(void *psess __unused)
{
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[4])
{
	switch (cmd) {
	case STATS_CMD_PAGER_STATS:
		return get_pager_stats(ptypes, params);
	case STATS_CMD_ALLOC_STATS:
		return get_alloc_stats(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static_ta_register(.uuid = STATS_UUID, .name = TA_NAME,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
