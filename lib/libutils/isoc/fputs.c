// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <trace.h>

int fputs(const char *s, FILE *stream)
{
	if (stream != stdout && stream != stderr)
		abort();

	trace_ext_puts(s);
	return 0;
}
