// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <printk.h>
#include <stdio.h>

int sprintf(char *str, const char *fmt, ...)
{
	int retval;
	va_list ap;

	va_start(ap, fmt);
	retval = __vsprintf(str, fmt, ap);
	va_end(ap);

	return retval;
}
