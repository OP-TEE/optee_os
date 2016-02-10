/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#endif /* UTEE_TYPES_H */
