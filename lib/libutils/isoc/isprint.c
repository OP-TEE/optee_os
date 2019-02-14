// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, KAIST
 */
#include <ctype.h>

int __builtin_isprint(int c)
{
	if (c >= 0x20 && c < 0x7f)
		return 1;
	return 0;
}
