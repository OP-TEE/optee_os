// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026, Jaehun Lee */
/* Per-invocation PC-derived edge feedback for the core fuzz TA. */
#include <kernel/core_fuzz_cov.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/thread.h>
#include <kernel/user_access.h>
#include <malloc.h>
#include <pta_core_fuzz_cov.h>
#include <stdint.h>
#include <string.h>

/* 0: idle, 1: preparing, 2: recording, 3: copying the completed map. */
static unsigned int recording;
static short owner_thread = -1;
static void *owner_token;
static uint32_t previous_site;
static uint8_t edge_map[PTA_CORE_FUZZ_COV_MAP_SIZE];

/* Called by GCC from tee_svc_cryp.c; keep this unit uninstrumented. */
void __sanitizer_cov_trace_pc(void)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	uintptr_t base = (uintptr_t)__text_start;
	uint32_t site = 0;
	uint32_t edge = 0;

	if (__atomic_load_n(&recording, __ATOMIC_ACQUIRE) != 2 ||
	    thread_get_id() != owner_thread || pc < base)
		return;
	if (pc >= (uintptr_t)__text_end) {
#ifdef CFG_WITH_PAGER
		if (pc < (uintptr_t)__text_pageable_start ||
		    pc >= (uintptr_t)__text_pageable_end)
#endif
			return;
	}

	/* Relative offsets survive core ASLR; pair PCs for edges. */
	site = (uint32_t)((pc - base) >> 2);
	edge = site ^ (previous_site >> 1);
	edge ^= edge >> 16;
	edge *= 0x7feb352dU;
	edge ^= edge >> 15;
	edge_map[edge & (PTA_CORE_FUZZ_COV_MAP_SIZE - 1)] = 1;
	previous_site = site;
}

static TEE_Result begin(void *token)
{
	unsigned int expected = 0;

	if (!__atomic_compare_exchange_n(&recording, &expected, 1, false,
					 __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return TEE_ERROR_BUSY;

	memset(edge_map, 0, sizeof(edge_map));
	owner_token = token;
	owner_thread = thread_get_id();
	previous_site = 0;
	__atomic_store_n(&recording, 2, __ATOMIC_RELEASE);
	return TEE_SUCCESS;
}

static TEE_Result end(void *token, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	if (__atomic_load_n(&recording, __ATOMIC_ACQUIRE) != 2 ||
	    owner_token != token || thread_get_id() != owner_thread)
		return TEE_ERROR_BAD_STATE;
	if (params[0].memref.size < sizeof(edge_map)) {
		params[0].memref.size = sizeof(edge_map);
		return TEE_ERROR_SHORT_BUFFER;
	}
	if (!params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	/* The caller is a user TA. copy_to_user() also supports CFG_PAN=y. */
	__atomic_store_n(&recording, 3, __ATOMIC_RELEASE);
	res = copy_to_user(params[0].memref.buffer, edge_map,
			   sizeof(edge_map));
	if (!res)
		params[0].memref.size = sizeof(edge_map);
	owner_thread = -1;
	owner_token = NULL;
	__atomic_store_n(&recording, 0, __ATOMIC_RELEASE);
	return res;
}

static TEE_Result open_session(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **session_ctx)
{
	static const TEE_UUID allowed = { 0x92ea581c, 0xd6ec, 0x449e,
		{ 0x9a, 0xa6, 0xcf, 0x93, 0xaa, 0x2b, 0x44, 0xdd } };
	struct ts_session *s = ts_get_calling_session();

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!s || !is_user_ta_ctx(s->ctx) ||
	    memcmp(&s->ctx->uuid, &allowed, sizeof(allowed)))
		return TEE_ERROR_ACCESS_DENIED;

	/* Allocate only for session ownership, never in the PC hook. */
	*session_ctx = malloc(1);
	if (!*session_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	return TEE_SUCCESS;
}

static void close_session(void *session_ctx)
{
	if (owner_token == session_ctx) {
		owner_token = NULL;
		owner_thread = -1;
		__atomic_store_n(&recording, 0, __ATOMIC_RELEASE);
	}
	free(session_ctx);
}

static TEE_Result invoke_command(void *session_ctx, uint32_t cmd,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CORE_FUZZ_COV_BEGIN:
		if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE))
			return TEE_ERROR_BAD_PARAMETERS;
		return begin(session_ctx);
	case PTA_CORE_FUZZ_COV_END:
		if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE))
			return TEE_ERROR_BAD_PARAMETERS;
		return end(session_ctx, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_CORE_FUZZ_COV_UUID, .name = "core_fuzz_cov",
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
