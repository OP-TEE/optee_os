// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#include <ctype.h>

int isdigit(int c)
{
	if (c >= '0' && c <= '9')
		return 1;
	return 0;
}
