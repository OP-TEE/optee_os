/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2018, Linaro Limited.
 */

#ifndef USER_TA_HEADER_H
#define USER_TA_HEADER_H

#include <tee_api_types.h>
#include <util.h>

#define TA_FLAG_USER_MODE		0	 /* Deprecated, was (1 << 0) */
#define TA_FLAG_EXEC_DDR		0	 /* Deprecated, was (1 << 1) */
#define TA_FLAG_SINGLE_INSTANCE		(1 << 2)
#define TA_FLAG_MULTI_SESSION		(1 << 3)
#define TA_FLAG_INSTANCE_KEEP_ALIVE	(1 << 4) /* remains after last close */
#define TA_FLAG_SECURE_DATA_PATH	(1 << 5) /* accesses SDP memory */
#define TA_FLAG_REMAP_SUPPORT		0	 /* Deprecated, was (1 << 6) */
#define TA_FLAG_CACHE_MAINTENANCE	(1 << 7) /* use cache flush syscall */
	/*
	 * TA instance can execute multiple sessions concurrently
	 * (pseudo-TAs only).
	 */
#define TA_FLAG_CONCURRENT		(1 << 8)
#define TA_FLAG_DEVICE_ENUM		(1 << 9) /* device enumeration */

#define TA_FLAGS_MASK			GENMASK_32(9, 0)

struct ta_head {
	TEE_UUID uuid;
	uint32_t stack_size;
	uint32_t flags;
	uint64_t depr_entry;
};

#if defined(CFG_FTRACE_SUPPORT)
#define FTRACE_RETFUNC_DEPTH		50
union compat_ptr {
	uint64_t ptr64;
	struct {
		uint32_t lo;
		uint32_t hi;
	} ptr32;
};

struct __ftrace_info {
	union compat_ptr buf_start;
	union compat_ptr buf_end;
	union compat_ptr ret_ptr;
};

struct ftrace_buf {
	uint64_t ret_func_ptr;	/* __ftrace_return pointer */
	uint64_t ret_stack[FTRACE_RETFUNC_DEPTH]; /* Return stack */
	uint32_t ret_idx;	/* Return stack index */
	uint32_t lr_idx;	/* lr index used for stack unwinding */
	uint64_t begin_time[FTRACE_RETFUNC_DEPTH]; /* Timestamp */
	uint64_t suspend_time;	/* Suspend timestamp */
	uint32_t curr_size;	/* Size of ftrace buffer */
	uint32_t max_size;	/* Max allowed size of ftrace buffer */
	uint32_t head_off;	/* Ftrace buffer header offset */
	uint32_t buf_off;	/* Ftrace buffer offset */
	bool syscall_trace_enabled; /* Some syscalls are never traced */
	bool syscall_trace_suspended; /* By foreign interrupt or RPC */
};

/* Defined by the linker script */
extern struct ftrace_buf __ftrace_buf_start;
extern uint8_t __ftrace_buf_end[];

unsigned long ftrace_return(void);
void __ftrace_return(void);
#endif

/*
 * Pointers to ELF initialization and finalization functions are extracted by
 * ldelf and stored on the TA heap. They can be accessed via the TA global
 * variable __init_fini_info::ifs, but the functions are meant to called via
 * __utee_call_elf_init_fn() and __utee_call_elf_fini_fn().
 */

struct __init_fini {
	uint32_t flags;
	uint16_t init_size;
	uint16_t fini_size;

	void (**init)(void); /* @init_size entries */
	void (**fini)(void); /* @fini_size entries */
};

#define __IFS_VALID		BIT(0)
#define __IFS_INIT_HAS_RUN	BIT(1)
#define __IFS_FINI_HAS_RUN	BIT(2)

struct __init_fini_info {
	uint32_t reserved;
	uint16_t size;
	uint16_t pad;
	struct __init_fini *ifs; /* @size entries */
};

/* 32-bit variants for a 64-bit ldelf to access a 32-bit TA */

struct __init_fini32 {
	uint32_t flags;
	uint16_t init_size;
	uint16_t fini_size;
	uint32_t init;
	uint32_t fini;
};

struct __init_fini_info32 {
	uint32_t reserved;
	uint16_t size;
	uint16_t pad;
	uint32_t ifs;
};

void __utee_call_elf_init_fn(void);
void __utee_call_elf_fini_fn(void);

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
