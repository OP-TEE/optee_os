// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <stdio.h>
#include <printk.h>

int snprintf(char *bf, size_t size, const char *fmt, ...)
{
	int retval;
	va_list ap;

	va_start(ap, fmt);
	retval = __vsnprintf(bf, size, fmt, ap, false);
	va_end(ap);

	return retval;
}

int vsnprintf(char *bf, size_t size, const char *fmt, va_list ap)
{
	return __vsnprintf(bf, size, fmt, ap, false);
}
