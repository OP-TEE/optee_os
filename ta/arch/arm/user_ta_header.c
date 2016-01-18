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
#include <compiler.h>
#include <tee_ta_api.h>
#include <tee_internal_api_extensions.h>
#include <user_ta_header.h>
#include <user_ta_header_defines.h>
#include <trace.h>

int trace_level = TRACE_LEVEL;

#ifdef TA_LOG_PREFIX
const char trace_ext_prefix[]  = TA_LOG_PREFIX;
#else
const char trace_ext_prefix[]  = "USER-TA";
#endif

#ifndef TA_VERSION
#define TA_VERSION "Undefined version"
#endif

#ifndef TA_DESCRIPTION
#define TA_DESCRIPTION "Undefined description"
#endif

/* exprted to user_ta_header.c, built within TA */
struct utee_params;

void __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id)
			__noreturn;

const struct ta_head ta_head __section(".ta_head") = {
	/* UUID, unique to each TA */
	.uuid = TA_UUID,
	.stack_size = TA_STACK_SIZE,
	.flags = TA_FLAG_USER_MODE | TA_FLAGS,
#ifdef __ILP32__
	/*
	 * This workaround is neded on 32-bit because it seems we can't
	 * initialize a 64-bit integer from the address of a function.
	 */
	.entry.ptr32 = { .lo = (uint32_t)__utee_entry },
#else
	.entry.ptr64 = (uint64_t)__utee_entry,
#endif
};

/* Keeping the heap in bss */
uint8_t ta_heap[TA_DATA_SIZE];
const size_t ta_heap_size = sizeof(ta_heap);

const struct user_ta_property ta_props[] = {
	{TA_PROP_STR_SINGLE_INSTANCE, USER_TA_PROP_TYPE_BOOL,
	 &(const bool){(TA_FLAGS & TA_FLAG_SINGLE_INSTANCE) != 0}},

	{TA_PROP_STR_MULTI_SESSION, USER_TA_PROP_TYPE_BOOL,
	 &(const bool){(TA_FLAGS & TA_FLAG_MULTI_SESSION) != 0}},

	{TA_PROP_STR_KEEP_ALIVE, USER_TA_PROP_TYPE_BOOL,
	 &(const bool){(TA_FLAGS & TA_FLAG_INSTANCE_KEEP_ALIVE) != 0}},

	{TA_PROP_STR_DATA_SIZE, USER_TA_PROP_TYPE_U32,
	 &(const uint32_t){TA_DATA_SIZE}},

	{TA_PROP_STR_STACK_SIZE, USER_TA_PROP_TYPE_U32,
	 &(const uint32_t){TA_STACK_SIZE}},

	{TA_PROP_STR_VERSION, USER_TA_PROP_TYPE_STRING,
	 TA_VERSION},

	{TA_PROP_STR_DESCRIPTION, USER_TA_PROP_TYPE_STRING,
	 TA_DESCRIPTION},

/*
 * Extended propietary properties, name of properties must not begin with
 * "gpd."
 */
#ifdef TA_CURRENT_TA_EXT_PROPERTIES
	TA_CURRENT_TA_EXT_PROPERTIES
#endif
};

const size_t ta_num_props = sizeof(ta_props) / sizeof(ta_props[0]);

int tahead_get_trace_level(void)
{
	/*
	 * Store trace level in TA head structure, as ta_head.prop_tracelevel
	 */
	return TRACE_LEVEL;
}
