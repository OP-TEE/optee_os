// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#include <ctype.h>

int __builtin_isalpha(int c)
{
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	return 0;
}
