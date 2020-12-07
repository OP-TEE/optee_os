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
	/*
	 * Device enumeration is done in two stages by the normal world, first
	 * before the tee-supplicant has started and then once more when the
	 * tee-supplicant is started. The flags below control if the TA should
	 * be reported in the first or second or case.
	 */
#define TA_FLAG_DEVICE_ENUM		(1 << 9)  /* without tee-supplicant */
#define TA_FLAG_DEVICE_ENUM_SUPP	(1 << 10) /* with tee-supplicant */

#define TA_FLAGS_MASK			GENMASK_32(10, 0)

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

void __utee_call_elf_init_fn(void);
void __utee_call_elf_fini_fn(void);

void __utee_tcb_init(void);

/*
 * Information about the ELF objects loaded by the application
 */

struct __elf_phdr_info {
	uint32_t reserved;
	uint16_t count;
	uint8_t reserved2;
	char zero;
	struct dl_phdr_info *dlpi; /* @count entries */
};

/* 32-bit variant for a 64-bit ldelf to access a 32-bit TA */
struct __elf_phdr_info32 {
	uint32_t reserved;
	uint16_t count;
	uint8_t reserved2;
	char zero;
	uint32_t dlpi;
};

extern struct __elf_phdr_info __elf_phdr_info;

#define TA_PROP_STR_SINGLE_INSTANCE	"gpd.ta.singleInstance"
#define TA_PROP_STR_MULTI_SESSION	"gpd.ta.multiSession"
#define TA_PROP_STR_KEEP_ALIVE		"gpd.ta.instanceKeepAlive"
#define TA_PROP_STR_DATA_SIZE		"gpd.ta.dataSize"
#define TA_PROP_STR_STACK_SIZE		"gpd.ta.stackSize"
#define TA_PROP_STR_VERSION		"gpd.ta.version"
#define TA_PROP_STR_DESCRIPTION		"gpd.ta.description"

enum user_ta_prop_type {
	USER_TA_PROP_TYPE_BOOL,	/* bool */
	USER_TA_PROP_TYPE_U32,	/* uint32_t */
	USER_TA_PROP_TYPE_UUID,	/* TEE_UUID */
	USER_TA_PROP_TYPE_IDENTITY,	/* TEE_Identity */
	USER_TA_PROP_TYPE_STRING,	/* zero terminated string of char */
	USER_TA_PROP_TYPE_BINARY_BLOCK,	/* zero terminated base64 coded string */
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

int tahead_get_trace_level(void);

#endif /* USER_TA_HEADER_H */
