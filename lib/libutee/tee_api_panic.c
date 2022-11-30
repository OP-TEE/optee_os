// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Linaro Limited
 */

#include <config.h>
#include <string.h>
#include <tee_api.h>
#include <utee_syscalls.h>
#include <util.h>

#include "tee_api_private.h"

#define ACCESS_RW	(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE)
#define ACCESS_W_ANY	(TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER)
#define ACCESS_R	TEE_MEMORY_ACCESS_READ
#define ACCESS_W	TEE_MEMORY_ACCESS_WRITE

/* System API - Misc */

void TEE_Panic(TEE_Result panicCode)
{
	_utee_panic(panicCode);
#ifdef __COVERITY__
	__coverity_panic__();
#endif
}

static void check_res(const char *msg __maybe_unused, TEE_Result res)
{
	if (res) {
		DMSG("%s: error %#"PRIx32, msg, res);
		TEE_Panic(0);
	}
}

static TEE_Result check_access(uint32_t flags, void *buf, size_t len)
{
	if (!len)
		return TEE_SUCCESS;

	if (!buf)
		return TEE_ERROR_SECURITY;

	if (IS_ENABLED(CFG_TA_STRICT_ANNOTATION_CHECKS))
		return TEE_CheckMemoryAccessRights(flags, buf, len);

	return TEE_SUCCESS;
}

void __utee_check_outbuf_annotation(void *buf, size_t *len)
{
	check_res("[outbuf] len",
		  check_access(ACCESS_RW, len, sizeof(*len)));
	check_res("[outbuf] buf",
		  check_access(ACCESS_W_ANY, buf, *len));
}

void __utee_check_gp11_outbuf_annotation(void *buf, uint32_t *len)
{
	check_res("[outbuf] len",
		  check_access(ACCESS_RW, len, sizeof(*len)));
	check_res("[outbuf] buf",
		  check_access(ACCESS_W_ANY, buf, *len));
}

void __utee_check_instring_annotation(const char *buf)
{
	check_res("[instring]",
		  check_access(ACCESS_R, (char *)buf, strlen(buf) + 1));
}

void __utee_check_outstring_annotation(char *buf, size_t *len)
{
	check_res("[outstring] len",
		  check_access(ACCESS_RW, len, sizeof(*len)));
	check_res("[outstring] buf",
		  check_access(ACCESS_W_ANY, buf, *len));
}

void __utee_check_gp11_outstring_annotation(char *buf, uint32_t *len)
{
	check_res("[outstring] len",
		  check_access(ACCESS_RW, len, sizeof(*len)));
	check_res("[outstring] buf",
		  check_access(ACCESS_W_ANY, buf, *len));
}

void __utee_check_out_annotation(void *buf, const size_t len)
{
	check_res("[out]",
		  check_access(ACCESS_W, buf, len));
}

void __utee_check_attr_in_annotation(const TEE_Attribute *attr, size_t count)
{
	check_res("[in] attr",
		  check_access(ACCESS_R, (void *)attr, sizeof(*attr) * count));
}

void __utee_check_gp11_attr_in_annotation(const __GP11_TEE_Attribute *attr,
					  size_t count)

{
	check_res("[in] attr",
		  check_access(ACCESS_R, (void *)attr, sizeof(*attr) * count));
}

void __utee_check_inout_annotation(void *buf, const size_t len)
{
	check_res("[inout]",
		  check_access(ACCESS_RW, buf, len));
}
