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

#ifndef USER_TA_HEADER_H
#define USER_TA_HEADER_H

#include <tee_api_types.h>

/* XXX */
#define TA_FLAG_USER_MODE 0

#define TA_FLAG_EXEC_DDR		(1 << 0)
#define TA_FLAG_SINGLE_INSTANCE		(1 << 1)
#define TA_FLAG_MULTI_SESSION		(1 << 2)
#define TA_FLAG_INSTANCE_KEEP_ALIVE	(1 << 3) /* remains after last close */
/*
 * TA_FLAG_UNSAFE_NW_PARAMS: May manipulate some secure memory based on
 * physical pointers from non-secure world
 */
#define TA_FLAG_UNSAFE_NW_PARAMS	(1 << 4)
#define TA_FLAG_REMAP_SUPPORT		(1 << 5) /* use map/unmap syscalls */
#define TA_FLAG_CACHE_MAINTENANCE	(1 << 6) /* use cache flush syscall */

struct ta_head {
	TEE_UUID uuid;
	uint32_t stack_size;
	uint32_t flags;
	uint32_t open_session;
	uint32_t close_session;
	uint32_t invoke_command;
};


#define TA_PROP_STR_SINGLE_INSTANCE	"gpd.ta.singleInstance"
#define TA_PROP_STR_MULTI_SESSION	"gpd.ta.multiSession"
#define TA_PROP_STR_KEEP_ALIVE		"gpd.ta.instanceKeepAlive"
#define TA_PROP_STR_DATA_SIZE		"gpd.ta.dataSize"
#define TA_PROP_STR_STACK_SIZE		"gpd.ta.stackSize"
#define TA_PROP_STR_VERSION		"gpd.ta.version"
#define TA_PROP_STR_DESCRIPTION		"gpd.ta.description"
#define TA_PROP_STR_UNSAFE_PARAM	"op-tee.unsafe_param"
#define TA_PROP_STR_REMAP		"op-tee.remap"
#define TA_PROP_STR_CACHE_SYNC		"op-tee.cache_sync"

enum user_ta_prop_type {
	USER_TA_PROP_TYPE_BOOL,	/* bool */
	USER_TA_PROP_TYPE_U32,	/* uint32_t */
	USER_TA_PROP_TYPE_UUID,	/* TEE_UUID */
	USER_TA_PROP_TYPE_IDENTITY,	/* TEE_Identity */
	USER_TA_PROP_TYPE_STRING,	/* zero terminated string of char */
	USER_TA_PROP_TYPE_BINARY_BLOCK,	/* zero terminated base64 coded string */
};

enum user_ta_core_service_id {
	USER_TA_CORE_ENTRY_MATH_INIT = 0x00000010,
	USER_TA_CORE_ENTRY_GARBAGE = 0x00000011,
	USER_TA_CORE_ENTRY_CLOSESESSION = 0x00000012,
};

struct user_ta_property {
	const char *name;
	enum user_ta_prop_type type;
	const void *value;
};

extern const struct user_ta_property ta_props[];
extern const size_t ta_num_props;

/* Needed by TEE_CheckMemoryAccessRights() */
extern uint32_t ta_param_types;
extern TEE_Param ta_params[4];

/* Trusted Application Function header */
typedef struct ta_func_head {
	uint32_t cmd_id;	/* Trusted Application Function ID */
	uint32_t start;		/* offset to start func */
} ta_func_head_t;

typedef struct {
	/* Same Prefix as ta_head_t */
	TEE_UUID uuid;
	const char *name;
	uint32_t flags;

	/* properties */
	uint32_t prop_datasize;
	uint32_t prop_stacksize;
	uint32_t prop_tracelevel;

	const ta_func_head_t *funcs;
	uint32_t nbr_func;
	 TEE_Result(*create_entry_point) (void);
	void (*destroy_entry_point) (void);
	 TEE_Result(*open_session_entry_point) (uint32_t nParamTypes,
					     TEE_Param pParams[4],
					     void **ppSessionContext);
	void (*close_session_entry_point) (void *pSessionContext);
	 TEE_Result(*invoke_command_entry_point) (void *pSessionContext,
					       uint32_t nCommandID,
					       uint32_t nParamTypes,
					       TEE_Param pParams[4]);
	 TEE_Result(*core_entries) (uint32_t nServiceId, uint32_t nParamTypes,
				   TEE_Param pParam[4]);
} ta_static_head_t;

int tahead_get_trace_level(void);

#endif /* USER_TA_HEADER_H */
