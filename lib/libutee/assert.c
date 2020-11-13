// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <compiler.h>
#include <trace.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_syscalls.h>

void _assert_log(const char *expr __maybe_unused,
		 const char *file __maybe_unused,
		 const int line __maybe_unused,
		 const char *func __maybe_unused)
{
	EMSG_RAW("assertion '%s' failed at %s:%d in %s()",
				expr, file, line, func);
}

void __noreturn _assert_break(void)
{
	_utee_panic(TEE_ERROR_GENERIC);
	/* Not reached */
	while (1)
		;
}
