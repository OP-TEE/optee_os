// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */

#include <trace.h>
#include "optee_sp_internal_api.h"

int trace_level = TRACE_LEVEL;

const char trace_ext_prefix[]  = "SP";

#if TRACE_LEVEL > 0

void trace_ext_puts(const char *str)
{
	optee_sp_log_puts(str);
}

int trace_ext_get_thread_id(void)
{
	return -1;
}

#endif  /* TRACE_LEVEL > 0 */
