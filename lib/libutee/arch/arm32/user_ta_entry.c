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

/* From user_ta_header.c, built within TA */
extern const size_t ta_data_size;

/* Exported to user_ta_header.c, built within TA */

void ta_entry_close_session(uint32_t session_id) __noreturn;

void ta_entry_open_session(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS],
			   uint32_t session_id) __noreturn;

void ta_entry_invoke_command(uint32_t cmd_id, uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS],
			     uint32_t session_id) __noreturn;

struct ta_session {
	uint32_t session_id;
	void *session_ctx;
	TAILQ_ENTRY(ta_session) link;
};

static TAILQ_HEAD(ta_sessions, ta_session) ta_sessions =
TAILQ_HEAD_INITIALIZER(ta_sessions);

static uint32_t ta_ref_count;
static bool context_init;

extern uint8_t *ta_heap_base;

uint32_t ta_param_types;
TEE_Param ta_params[TEE_NUM_PARAMS];

static void ta_header_save_params(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	ta_param_types = param_types;
	if (params != NULL)
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
	if (itr != NULL)
		return TEE_SUCCESS;

	ta_ref_count++;

	if (ta_ref_count == 1) {
		TEE_Result res;

		if (!context_init) {
			trace_set_level(tahead_get_trace_level());
			malloc_init(ta_heap_base, ta_data_size);
			_TEE_MathAPI_Init();
			context_init = true;
		}

		res = TA_CreateEntryPoint();
		if (res != TEE_SUCCESS)
			return res;
	}

	itr =
	    TEE_Malloc(sizeof(struct ta_session),
		       TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (itr == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	itr->session_id = session_id;
	itr->session_ctx = 0;
	TAILQ_INSERT_TAIL(&ta_sessions, itr, link);

	return TEE_SUCCESS;
}

static void ta_header_remove_session(uint32_t session_id)
{
	struct ta_session *itr;
	TAILQ_FOREACH(itr, &ta_sessions, link) {
		if (itr->session_id == session_id) {
			TAILQ_REMOVE(&ta_sessions, itr, link);
			TEE_Free(itr);

			ta_ref_count--;
			if (ta_ref_count == 0)
				TA_DestroyEntryPoint();

			return;
		}
	}
}

void /*__attribute__((noreturn))*/ ta_entry_open_session(
					 uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS],
					 uint32_t session_id)
{
	TEE_Result res;
	struct ta_session *session;

	res = ta_header_add_session(session_id);
	if (res != TEE_SUCCESS)
		goto function_exit;

	session = ta_header_get_session(session_id);
	if (session == NULL)
		goto function_exit;

	ta_header_save_params(param_types, params);
	res =
	    TA_OpenSessionEntryPoint(param_types, params,
				     &session->session_ctx);
	if (res != TEE_SUCCESS) {
		ta_header_remove_session(session_id);
		goto function_exit;
	}

function_exit:
	ta_header_save_params(0, NULL);
	utee_return(res);
}

void /*__attribute__((noreturn))*/ ta_entry_close_session(uint32_t session_id)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct ta_session *session;

	session = ta_header_get_session(session_id);
	if (session == NULL)
		goto function_exit;

	TA_CloseSessionEntryPoint(session->session_ctx);

	ta_header_remove_session(session_id);

	res = TEE_SUCCESS;
function_exit:
	utee_return(res);
}

void /*__attribute__((noreturn))*/ ta_entry_invoke_command(
				uint32_t cmd_id,
				uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS],
				uint32_t session_id)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct ta_session *session;

	session = ta_header_get_session(session_id);
	if (session == NULL)
		goto function_exit;

	ta_header_save_params(param_types, params);

	res =
	    TA_InvokeCommandEntryPoint(session->session_ctx, cmd_id,
				       param_types, params);

function_exit:
	ta_header_save_params(0, NULL);
	utee_return(res);
}
