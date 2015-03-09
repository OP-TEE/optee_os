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

/* exprted to user_ta_header.c, built within TA */
void ta_entry_close_session(uint32_t session_id) __noreturn;

void ta_entry_open_session(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS],
			   uint32_t session_id) __noreturn;

void ta_entry_invoke_command(uint32_t cmd_id, uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS],
			     uint32_t session_id) __noreturn;

/* These externs are defined in the ld link script */
extern uint32_t linker_RO_sections_size;
extern uint32_t linker_RW_sections_size;
extern uint32_t linker_res_funcs_ZI_sections_size;
extern uint32_t linker_rel_dyn_GOT;

/* Note that cmd_id is not used in a User Mode TA */
const struct user_ta_func_head user_ta_func_head[]
			__attribute__ ((section(".ta_func_head"))) = {
	{ 0, (uint32_t)ta_entry_open_session },
	{ 0, (uint32_t)ta_entry_close_session },
	{ 0, (uint32_t)ta_entry_invoke_command },
	{ (TA_FLAG_USER_MODE | TA_FLAGS), 0 /* Spare */ },
	{ (TA_DATA_SIZE), (TA_STACK_SIZE) },
};

const struct user_ta_head ta_head __attribute__ ((section(".ta_head"))) = {
	/* UUID, unique to each TA */
	TA_UUID,
	/* Number of functions in the TA */
	sizeof(user_ta_func_head) / sizeof(struct user_ta_func_head),
	/* Section size information */
	(uint32_t)&linker_RO_sections_size,
	(uint32_t)&linker_RW_sections_size,
	(uint32_t)&linker_res_funcs_ZI_sections_size,
	(uint32_t)&linker_rel_dyn_GOT,
	/* Hash type, filled in by sign-tool */
	0,
	/* TA trace level */
	/* TA_TRACE_LEVEL_DEFAULT, */
};

/* Filled in by TEE Core when loading the TA */
uint8_t *ta_heap_base __attribute__ ((section(".ta_heap_base")));

const size_t ta_data_size = TA_DATA_SIZE;

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
