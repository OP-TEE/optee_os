// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <compiler.h>
#include <printk.h>
#include <stdio.h>
#include <stdlib.h>

int sprintf(char *str, const char *fmt, ...)
{
	int retval;
	va_list ap;

	va_start(ap, fmt);
	retval = __vsprintf(str, fmt, ap);
	va_end(ap);

	return retval;
}

int __sprintf_chk(char *str, int flag __unused, size_t slen,
		  const char *fmt, ...)
{
	int retval;
	va_list ap;

	if (slen == 0)
		abort();

	va_start(ap, fmt);
	retval = __vsnprintf(str, slen, fmt, ap, false);
	va_end(ap);

	if (retval > 0 && (size_t)retval >= slen)
		abort();

	return retval;
}
