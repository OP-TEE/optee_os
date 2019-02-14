// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, KAIST
 */
#include <ctype.h>

int __builtin_islower(int c)
{
	return (c >= 'a' && c <= 'z');
}
