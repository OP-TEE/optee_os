// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#include <ctype.h>

int __builtin_isspace(int c)
{
	return (c == ' ');
}
