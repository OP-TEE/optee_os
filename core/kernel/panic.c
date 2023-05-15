// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <trace.h>

void __do_panic(const char *file __maybe_unused,
		const int line __maybe_unused,
		const char *func __maybe_unused,
		const char *msg __maybe_unused)
{
	/* disable prehemption */
	(void)thread_mask_exceptions(THREAD_EXCP_ALL);

	/* TODO: notify other cores */

	/* trace: Panic ['panic-string-message' ]at FILE:LINE [<FUNCTION>]" */
	if (!file && !func && !msg)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic %s%s%sat %s:%d %s%s%s",
			 msg ? "'" : "", msg ? msg : "", msg ? "' " : "",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");

	print_kernel_stack();
	/* abort current execution */
	while (1)
		cpu_idle();
}

void __weak cpu_idle(void)
{
}
