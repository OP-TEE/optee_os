// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
#include <config.h>
#include <malloc.h>
#include <tee_ta_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <user_ta_header.h>
#include <user_ta_header_defines.h>
#include <utee_syscalls.h>

extern void *__stack_chk_guard;

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

#ifdef ARM32
#define _C_FUNCTION(name) name##_c
#else
#define _C_FUNCTION(name) name
#endif /* ARM32 */

/* From libutee */
TEE_Result __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id);

void __noreturn _C_FUNCTION(__ta_entry)(unsigned long func,
					unsigned long session_id,
					struct utee_params *up,
					unsigned long cmd_id);

void __noreturn _C_FUNCTION(__ta_entry)(unsigned long func,
					unsigned long session_id,
					struct utee_params *up,
					unsigned long cmd_id)
{
	static bool stack_canary_inited;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (IS_ENABLED(_CFG_TA_STACK_PROTECTOR) && !stack_canary_inited) {
		uintptr_t canary = 0;

		res = _utee_cryp_random_number_generate(&canary,
							sizeof(canary));
		if (res != TEE_SUCCESS)
			_utee_return(res);

		/* Leave null byte in canary to prevent string base exploit */
		canary &= ~0xffUL;

		__stack_chk_guard = (void *)canary;
		stack_canary_inited = true;
	}

	res = __utee_entry(func, session_id, up, cmd_id);

#if defined(CFG_FTRACE_SUPPORT)
	/*
	 * __ta_entry is the first TA API called from TEE core. As it being
	 * __noreturn API, we need to call ftrace_return in this API just
	 * before _utee_return syscall to get proper ftrace call graph.
	 */
	ftrace_return();
#endif

	_utee_return(res);
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
#if TA_DATA_SIZE < MALLOC_INITIAL_POOL_MIN_SIZE
#error TA_DATA_SIZE too small
#endif

uint8_t ta_heap[TA_DATA_SIZE];
const size_t ta_heap_size = sizeof(ta_heap);

#ifndef TA_NO_SHARE_DATA_SIZE
#define TA_NO_SHARE_DATA_SIZE	0
#endif
#if TA_NO_SHARE_DATA_SIZE && \
	TA_NO_SHARE_DATA_SIZE < MALLOC_INITIAL_POOL_MIN_SIZE
#error TA_NO_SHARE_DATA_SIZE too small
#endif

uint8_t __ta_no_share_heap[TA_NO_SHARE_DATA_SIZE];
const size_t __ta_no_share_heap_size = sizeof(__ta_no_share_heap);

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

	/* Only little-endian supported */
	{TA_PROP_STR_ENDIAN, USER_TA_PROP_TYPE_U32, &(const uint32_t){0}},

	{TA_PROP_STR_DOES_NOT_CLOSE_HANDLE_ON_CORRUPT_OBJECT,
	 USER_TA_PROP_TYPE_BOOL,
	 &(const bool){TA_FLAGS & TA_FLAG_DONT_CLOSE_HANDLE_ON_CORRUPT_OBJECT}},

/*
 * Extended propietary properties, name of properties must not begin with
 * "gpd."
 */
#ifdef TA_CURRENT_TA_EXT_PROPERTIES
	TA_CURRENT_TA_EXT_PROPERTIES
#endif
};

const size_t ta_num_props = sizeof(ta_props) / sizeof(ta_props[0]);

#ifdef CFG_FTRACE_SUPPORT
struct __ftrace_info __ftrace_info = {
#ifdef __ILP32__
	.buf_start.ptr32 = { .lo = (uint32_t)&__ftrace_buf_start },
	.buf_end.ptr32 = { .lo = (uint32_t)__ftrace_buf_end },
	.ret_ptr.ptr32 = { .lo = (uint32_t)&__ftrace_return },
#else
	.buf_start.ptr64 = (uint64_t)&__ftrace_buf_start,
	.buf_end.ptr64 = (uint64_t)__ftrace_buf_end,
	.ret_ptr.ptr64 = (uint64_t)&__ftrace_return,
#endif
};
#endif

int tahead_get_trace_level(void)
{
	/*
	 * Store trace level in TA head structure, as ta_head.prop_tracelevel
	 */
	return TRACE_LEVEL;
}

#if __OPTEE_CORE_API_COMPAT_1_1
#undef TA_OpenSessionEntryPoint
#undef TA_InvokeCommandEntryPoint
#undef TEE_Param
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS],
				    void **sess_ctx)
{
	return __ta_open_sess(pt, params, sess_ctx,
			      __GP11_TA_OpenSessionEntryPoint);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	return __ta_invoke_cmd(sess_ctx, cmd_id, pt, params,
			       __GP11_TA_InvokeCommandEntryPoint);
}
#endif
