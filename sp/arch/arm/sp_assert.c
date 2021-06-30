// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */

#include <assert.h>
#include <trace.h>
#include "compiler.h"
#include "optee_sp_internal_api.h"

/*
 * Log function called on assert fail. It calls the generic trace function of
 * libutils.
 */
void _assert_log(const char *expr __maybe_unused,
		 const char *file __maybe_unused,
		 const int line __maybe_unused,
		 const char *func __maybe_unused)
{
	EMSG_RAW("assertion '%s' failed at %s:%d in %s()", expr, file, line,
		 func);
}

/*
 * On assert fail the _assert_break function is called as a last step where the
 * handling of the error should be specified.
 */
void __noreturn _assert_break(void)
{
	/* Forwarding call to user defined function. */
	optee_sp_panic();
}
