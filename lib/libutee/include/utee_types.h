/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef UTEE_TYPES_H
#define UTEE_TYPES_H

#include <inttypes.h>
#include <tee_api_defines.h>

enum utee_time_category {
	UTEE_TIME_CAT_SYSTEM = 0,
	UTEE_TIME_CAT_TA_PERSISTENT,
	UTEE_TIME_CAT_REE
};

enum utee_entry_func {
	UTEE_ENTRY_FUNC_OPEN_SESSION = 0,
	UTEE_ENTRY_FUNC_CLOSE_SESSION,
	UTEE_ENTRY_FUNC_INVOKE_COMMAND,
	/*
	 * UTEE_ENTRY_FUNC_DUMP_MEMSTATS
	 * [out] value[0].a  Byte size currently allocated
	 * [out] value[0].b  Max bytes allocated since stats reset
	 * [out] value[1].a  Pool byte size
	 * [out] value[1].b  Number of failed allocation requests
	 * [out] value[2].a  Biggest byte size which allocation failed
	 * [out] value[2].b  Biggest byte size which allocation succeeded
	 */
	UTEE_ENTRY_FUNC_DUMP_MEMSTATS,
};

/*
 * Cache operation types.
 * Used when extensions TEE_CacheClean() / TEE_CacheFlush() /
 * TEE_CacheInvalidate() are used
 */
enum utee_cache_operation {
	TEE_CACHECLEAN = 0,
	TEE_CACHEFLUSH,
	TEE_CACHEINVALIDATE,
};

struct utee_params {
	uint64_t types;
	/* vals[n * 2]	   corresponds to either value.a or memref.buffer
	 * vals[n * 2 + ]  corresponds to either value.b or memref.size
	 * when converting to/from struct tee_ta_param
	 */
	uint64_t vals[TEE_NUM_PARAMS * 2];
};

struct utee_attribute {
	uint64_t a;	/* also serves as a pointer for references */
	uint64_t b;	/* also serves as a length for references */
	uint32_t attribute_id;
};

struct utee_object_info {
	uint32_t obj_type;
	uint32_t obj_size;
	uint32_t max_obj_size;
	uint32_t obj_usage;
	uint32_t data_size;
	uint32_t data_pos;
	uint32_t handle_flags;
};

#endif /* UTEE_TYPES_H */
