/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2018, Linaro Limited.
 */

#ifndef USER_TA_HEADER_H
#define USER_TA_HEADER_H

#include <tee_api_types.h>
#include <util.h>

#define TA_FLAG_SINGLE_INSTANCE		(1 << 2)
#define TA_FLAG_MULTI_SESSION		(1 << 3)
#define TA_FLAG_INSTANCE_KEEP_ALIVE	(1 << 4) /* remains after last close */
#define TA_FLAG_SECURE_DATA_PATH	(1 << 5) /* accesses SDP memory */
#define TA_FLAG_REMAP_SUPPORT		(1 << 6) /* use map/unmap syscalls */
#define TA_FLAG_CACHE_MAINTENANCE	(1 << 7) /* use cache flush syscall */
	/*
	 * TA instance can execute multiple sessions concurrently
	 * (pseudo-TAs only).
	 */
#define TA_FLAG_CONCURRENT		(1 << 8)
#define TA_FLAG_DEVICE_ENUM		(1 << 9) /* device enumeration */

#define TA_FLAGS_MASK			GENMASK_32(9, 2)

/* Deprecated macros that will be removed in the 3.2 release */
#define TA_FLAG_USER_MODE		0
#define TA_FLAG_EXEC_DDR		0

union ta_head_func_ptr {
	uint64_t ptr64;
	struct ta_head_func_ptr32 {
		uint32_t lo;
		uint32_t hi;
	} ptr32;
};

struct ta_head {
	TEE_UUID uuid;
	uint32_t stack_size;
	uint32_t flags;
	union ta_head_func_ptr entry;
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
extern TEE_Param ta_params[TEE_NUM_PARAMS];

/* Trusted Application Function header */
typedef struct ta_func_head {
	uint32_t cmd_id;	/* Trusted Application Function ID */
	uint32_t start;		/* offset to start func */
} ta_func_head_t;

int tahead_get_trace_level(void);

#endif /* USER_TA_HEADER_H */
