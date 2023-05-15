// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, KAIST
 */
#include <ctype.h>

int toupper(int c)
{
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 'A';
	return c;
}
