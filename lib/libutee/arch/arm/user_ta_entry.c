// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
#include <stdbool.h>
#include <string.h>
#include <sys/queue.h>
#include <tee_api.h>
#include <tee_ta_api.h>
#include <tee_internal_api_extensions.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include "utee_misc.h"
#include <tee_arith_internal.h>
#include <malloc.h>
#include "tee_api_private.h"

/*
 * Pull in symbol __utee_mcount.
 * This symbol is implemented in assembly in its own compilation unit, and is
 * never referenced except by the linker script (in a PROVIDE() command).
 * Because the compilation units are packed into an archive (libutee.a), the
 * linker will discard the compilation units that are not explicitly
 * referenced. AFAICT this occurs *before* the linker processes the PROVIDE()
 * command, resulting in an "undefined symbol" error. We avoid this by
 * adding an explicit reference here.
 */
extern uint8_t __utee_mcount[];
void *_ref__utee_mcount __unused = &__utee_mcount;

struct ta_session {
	uint32_t session_id;
	void *session_ctx;
	TAILQ_ENTRY(ta_session) link;
};

static TAILQ_HEAD(ta_sessions, ta_session) ta_sessions =
		TAILQ_HEAD_INITIALIZER(ta_sessions);

static bool init_done;

/* From user_ta_header.c, built within TA */
extern uint8_t ta_heap[];
extern const size_t ta_heap_size;
extern struct ta_head ta_head;

uint32_t ta_param_types;
TEE_Param ta_params[TEE_NUM_PARAMS];

static TEE_Result init_instance(void)
{
	trace_set_level(tahead_get_trace_level());
	__utee_gprof_init();
	malloc_add_pool(ta_heap, ta_heap_size);
	_TEE_MathAPI_Init();
	return TA_CreateEntryPoint();
}

static void uninit_instance(void)
{
	__utee_gprof_fini();
	TA_DestroyEntryPoint();
}

static void ta_header_save_params(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	ta_param_types = param_types;

	if (params)
		memcpy(ta_params, params, sizeof(ta_params));
	else
		memset(ta_params, 0, sizeof(ta_params));
}

static struct ta_session *ta_header_get_session(uint32_t session_id)
{
	struct ta_session *itr;

	TAILQ_FOREACH(itr, &ta_sessions, link) {
		if (itr->session_id == session_id)
			return itr;
	}
	return NULL;
}

static TEE_Result ta_header_add_session(uint32_t session_id)
{
	struct ta_session *itr = ta_header_get_session(session_id);
	TEE_Result res;

	if (itr)
		return TEE_SUCCESS;

	if (!init_done) {
		init_done = true;
		res = init_instance();
		if (res)
			return res;
	}

	itr = TEE_Malloc(sizeof(struct ta_session),
			TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!itr)
		return TEE_ERROR_OUT_OF_MEMORY;
	itr->session_id = session_id;
	itr->session_ctx = 0;
	TAILQ_INSERT_TAIL(&ta_sessions, itr, link);

	return TEE_SUCCESS;
}

static void ta_header_remove_session(uint32_t session_id)
{
	struct ta_session *itr;
	bool keep_alive;

	TAILQ_FOREACH(itr, &ta_sessions, link) {
		if (itr->session_id == session_id) {
			TAILQ_REMOVE(&ta_sessions, itr, link);
			TEE_Free(itr);

			keep_alive =
				(ta_head.flags & TA_FLAG_SINGLE_INSTANCE) &&
				(ta_head.flags & TA_FLAG_INSTANCE_KEEP_ALIVE);
			if (TAILQ_EMPTY(&ta_sessions) && !keep_alive)
				uninit_instance();

			return;
		}
	}
}

static TEE_Result entry_open_session(unsigned long session_id,
			struct utee_params *up)
{
	TEE_Result res;
	struct ta_session *session;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	res = ta_header_add_session(session_id);
	if (res != TEE_SUCCESS)
		return res;

	session = ta_header_get_session(session_id);
	if (!session)
		return TEE_ERROR_BAD_STATE;

	__utee_to_param(params, &param_types, up);
	ta_header_save_params(param_types, params);

	res = TA_OpenSessionEntryPoint(param_types, params,
				       &session->session_ctx);

	__utee_from_param(up, param_types, params);

	if (res != TEE_SUCCESS)
		ta_header_remove_session(session_id);
	return res;
}

static TEE_Result entry_close_session(unsigned long session_id)
{
	struct ta_session *session = ta_header_get_session(session_id);

	if (!session)
		return TEE_ERROR_BAD_STATE;

	TA_CloseSessionEntryPoint(session->session_ctx);

	ta_header_remove_session(session_id);
	return TEE_SUCCESS;
}

static TEE_Result entry_invoke_command(unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id)
{
	TEE_Result res;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];
	struct ta_session *session = ta_header_get_session(session_id);

	if (!session)
		return TEE_ERROR_BAD_STATE;

	__utee_to_param(params, &param_types, up);
	ta_header_save_params(param_types, params);

	res = TA_InvokeCommandEntryPoint(session->session_ctx, cmd_id,
					 param_types, params);

	__utee_from_param(up, param_types, params);
	return res;
}

void __noreturn __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id)
{
	TEE_Result res;

#if defined(ARM32) && defined(CFG_UNWIND)
	/*
	 * This function is the bottom of the user call stack: mark it as such
	 * so that the unwinding code won't try to go further down.
	 */
	asm(".cantunwind");
#endif

	switch (func) {
	case UTEE_ENTRY_FUNC_OPEN_SESSION:
		res = entry_open_session(session_id, up);
		break;
	case UTEE_ENTRY_FUNC_CLOSE_SESSION:
		res = entry_close_session(session_id);
		break;
	case UTEE_ENTRY_FUNC_INVOKE_COMMAND:
		res = entry_invoke_command(session_id, up, cmd_id);
		break;
	default:
		res = 0xffffffff;
		TEE_Panic(0);
		break;
	}
	ta_header_save_params(0, NULL);
	utee_return(res);
}
