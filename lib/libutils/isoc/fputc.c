// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <stdlib.h>

int fputc(int c, FILE *stream)
{
	if (stream != stdout && stream != stderr)
		abort();

	return putchar(c);
}
