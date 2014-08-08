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

/*
 * The generic format of a TA header.
 *
 * signed_header
 * ta_head_t
 * ta_func_head_t (1)
 * ta_func_head_t (2)
 * ...
 * ta_func_head_t (N) N = ta_head(_t).nbr_func
 * func_1
 * func_1
 * ...
 * func_N
 * hash_1
 * hash_2
 * ...
 * hash_M
 *
 * The currently this format is limited to N = 5, resulting in a TA header as
 *
 * signed_header
 * struct user_ta_head
 * struct user_ta_func_head (1)
 * struct user_ta_func_head (2)
 * struct user_ta_func_head (3)
 * struct user_ta_sub_head
 *
 * Note that the last two func heads are replaced by struct user_ta_sub_head.
 */

struct user_ta_head {
	TEE_UUID uuid;
	uint32_t nbr_func;
	uint32_t ro_size;
	uint32_t rw_size;
	uint32_t zi_size;
	uint32_t got_size;
	uint32_t hash_type;
};

#define USER_TA_HEAD_FLAG_USER_MODE 0x80000000UL
#define USER_TA_HEAD_FLAG_DDR_EXEC  0x40000000UL

struct user_ta_func_head {
	uint32_t cmd_id;
	uint32_t start;		/* offset to start func */
};

struct user_ta_sub_head {
	uint32_t flags;
	uint32_t spare;
	uint32_t heap_size;
	uint32_t stack_size;
};

#define TA_FLAG_USER_MODE           (1 << 0)
#define TA_FLAG_EXEC_DDR            (1 << 1)
#define TA_FLAG_SINGLE_INSTANCE     (1 << 2)
#define TA_FLAG_MULTI_SESSION       (1 << 3)
#define TA_FLAG_INSTANCE_KEEP_ALIVE (1 << 4)
/*
 * TEE Core will allow memrefs in some firewalled memory if this flag is
 * set for a User TA.
 */
#define TA_FLAG_UNSAFE_NW_PARAMS    (1 << 5)

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
