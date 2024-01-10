// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <compiler.h>
#include <drivers/clk.h>
#include <drivers/regulator.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_time.h>
#include <malloc.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <pta_stats.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <trace.h>

static TEE_Result get_alloc_stats(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	struct pta_stats_alloc *stats = NULL;
	uint32_t size_to_retrieve = 0;
	uint32_t pool_id = 0;
	uint32_t i = 0;

	/*
	 * p[0].value.a = pool id (from 0 to n)
	 *   - 0 means all the pools to be retrieved
	 *   - 1..n means pool id
	 * p[0].value.b = 0 if no reset of the stats
	 * p[1].memref.buffer = output buffer to struct pta_stats_alloc
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

	size_to_retrieve = sizeof(struct pta_stats_alloc);
	if (pool_id == ALLOC_ID_ALL)
		size_to_retrieve *= STATS_NB_POOLS;

	if (p[1].memref.size < size_to_retrieve) {
		p[1].memref.size = size_to_retrieve;
		return TEE_ERROR_SHORT_BUFFER;
	}
	p[1].memref.size = size_to_retrieve;
	stats = p[1].memref.buffer;

	for (i = ALLOC_ID_HEAP; i <= STATS_NB_POOLS; i++) {
		if (pool_id != ALLOC_ID_ALL && i != pool_id)
			continue;

		switch (i) {
		case ALLOC_ID_HEAP:
			malloc_get_stats(stats);
			strlcpy(stats->desc, "Heap", sizeof(stats->desc));
			if (p[0].value.b)
				malloc_reset_stats();
			break;

		case ALLOC_ID_PUBLIC_DDR:
			EMSG("public DDR not managed by secure side anymore");
			break;

		case ALLOC_ID_TA_RAM:
			tee_mm_get_pool_stats(&tee_mm_sec_ddr, stats,
					      !!p[0].value.b);
			strlcpy(stats->desc, "Secure DDR", sizeof(stats->desc));
			break;

#ifdef CFG_NS_VIRTUALIZATION
		case ALLOC_ID_NEXUS_HEAP:
			nex_malloc_get_stats(stats);
			strlcpy(stats->desc, "KHeap", sizeof(stats->desc));
			if (p[0].value.b)
				nex_malloc_reset_stats();
			break;
#endif
		default:
			EMSG("Wrong pool id");
			break;
		}

		stats++;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_pager_stats(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	struct tee_pager_stats stats = { };

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

static TEE_Result get_memleak_stats(uint32_t type,
				    TEE_Param p[TEE_NUM_PARAMS] __maybe_unused)
{

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) != type)
		return TEE_ERROR_BAD_PARAMETERS;

	mdbg_check(1);

	return TEE_SUCCESS;
}

static TEE_Result get_user_ta_stats(uint32_t type,
				    TEE_Param p[TEE_NUM_PARAMS] __maybe_unused)
{
	uint32_t res = TEE_SUCCESS;

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != type)
		return TEE_ERROR_BAD_PARAMETERS;

#if defined(CFG_TA_STATS)
	res = tee_ta_instance_stats(p[0].memref.buffer,
				    &p[0].memref.size);
	if (res != TEE_SUCCESS)
		DMSG("tee_ta_dump_stats return: 0x%"PRIx32, res);
#else
	res = TEE_ERROR_NOT_SUPPORTED;
#endif
	return res;
}

static TEE_Result get_system_time(uint32_t type,
				  TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	TEE_Time ree_time = { };
	TEE_Time tee_time = { };

	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != type)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = tee_time_get_sys_time(&tee_time);
	if (ret)
		return ret;

	ret = tee_time_get_ree_time(&ree_time);
	if (ret)
		return ret;

	p[0].value.a = ree_time.seconds;
	p[0].value.b = ree_time.millis;
	p[1].value.a = tee_time.seconds;
	p[1].value.b = tee_time.millis;

	return TEE_SUCCESS;
}

static TEE_Result print_driver_info(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != type)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (p[0].value.a) {
	case STATS_DRIVER_TYPE_CLOCK:
		clk_print_tree();
		break;
	case STATS_DRIVER_TYPE_REGULATOR:
		regulator_print_tree();
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case STATS_CMD_PAGER_STATS:
		return get_pager_stats(ptypes, params);
	case STATS_CMD_ALLOC_STATS:
		return get_alloc_stats(ptypes, params);
	case STATS_CMD_MEMLEAK_STATS:
		return get_memleak_stats(ptypes, params);
	case STATS_CMD_TA_STATS:
		return get_user_ta_stats(ptypes, params);
	case STATS_CMD_GET_TIME:
		return get_system_time(ptypes, params);
	case STATS_CMD_PRINT_DRIVER_INFO:
		return print_driver_info(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = STATS_UUID, .name = "stats.pta",
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
