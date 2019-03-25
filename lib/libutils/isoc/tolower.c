// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <ctype.h>

int tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}
