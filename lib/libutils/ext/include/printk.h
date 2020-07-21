/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015 Linaro Limited
 */

/*
 * This file provides extensions to the standard snprintf() and vsnprintf()
 * functions. These 'k' variants support additional formats.
 */

#ifndef PRINTK_H
#define PRINTK_H

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>

int snprintk(char *str, size_t size, const char *fmt, ...)
		    __attribute__((__format__(__printf__, 3, 4)));
int vsnprintk(char *str, size_t size, const char *fmt, va_list ap)
		    __attribute__((__format__(__printf__, 3, 0)));

int __vsnprintf(char *str, size_t size, const char *fmt, va_list ap,
		bool ext) __attribute__((__format__(__printf__, 3, 0)));
int __vsprintf(char *bf, const char *fmt, va_list ap)
			__attribute__((__format__(__printf__, 2, 0)));

#endif /* PRINTK_H */
