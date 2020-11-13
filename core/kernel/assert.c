// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <compiler.h>
#include <trace.h>
#include <kernel/panic.h>

/* assert log and break for the optee kernel */

void __nostackcheck _assert_log(const char *expr __maybe_unused,
				const char *file __maybe_unused,
				const int line __maybe_unused,
				const char *func __maybe_unused)
{
#if defined(CFG_TEE_CORE_DEBUG)
	EMSG_RAW("assertion '%s' failed at %s:%d <%s>",
		 expr, file, line, func);
#else
	EMSG_RAW("assertion failed");
#endif
}

void __noreturn _assert_break(void)
{
	panic();
}
