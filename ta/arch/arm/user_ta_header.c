// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
#include <tee_ta_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <user_ta_header.h>
#include <user_ta_header_defines.h>
#include <utee_syscalls.h>

int trace_level = TRACE_LEVEL;

const char trace_ext_prefix[]  = "TA";

#ifndef TA_VERSION
#define TA_VERSION "Undefined version"
#endif

#ifndef TA_DESCRIPTION
#define TA_DESCRIPTION "Undefined description"
#endif

/* exprted to user_ta_header.c, built within TA */
struct utee_params;

TEE_Result __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id);

void __noreturn __ta_entry(unsigned long func, unsigned long session_id,
			   struct utee_params *up, unsigned long cmd_id);

void __noreturn __ta_entry(unsigned long func, unsigned long session_id,
			   struct utee_params *up, unsigned long cmd_id)
{
	TEE_Result res = TEE_SUCCESS;

	res = __utee_entry(func, session_id, up, cmd_id);

	utee_return(res);
}

/*
 * According to GP Internal API, TA_STACK_SIZE corresponds to the stack
 * size used by the TA code itself and does not include stack space
 * possibly used by the Trusted Core Framework.
 * Hence, stack_size which is the size of the stack to use,
 * must be enlarged
 * It has been set to 2048 to include trace framework and invoke commands
 */
#define TA_FRAMEWORK_STACK_SIZE 2048

const struct ta_head ta_head __section(".ta_head") = {
	/* UUID, unique to each TA */
	.uuid = TA_UUID,
	/*
	 * According to GP Internal API, TA_FRAMEWORK_STACK_SIZE corresponds to
	 * the stack size used by the TA code itself and does not include stack
	 * space possibly used by the Trusted Core Framework.
	 * Hence, stack_size which is the size of the stack to use,
	 * must be enlarged
	 */
	.stack_size = TA_STACK_SIZE + TA_FRAMEWORK_STACK_SIZE,
	.flags = TA_FLAGS,
	/*
	 * The TA entry doesn't go via this field any longer, to be able to
	 * reliably check that an old TA isn't loaded set this field to a
	 * fixed value.
	 */
	.depr_entry = UINT64_MAX,
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
