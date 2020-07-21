/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef STDIO_H
#define STDIO_H

#include <stddef.h>
#include <stdarg.h>

typedef struct _FILE FILE;

int printf(const char *fmt, ...)
                    __attribute__ ((__format__ (__printf__, 1, 2)));
/* sprintf() is unsafe and should not be used. Prefer snprintf(). */
int sprintf(char *str, const char *fmt, ...)
                    __attribute__ ((__format__ (__printf__, 2, 3)))
                    __attribute__ ((deprecated));
int snprintf(char *str, size_t size, const char *fmt, ...)
                    __attribute__ ((__format__ (__printf__, 3, 4)));
int vsnprintf (char *str, size_t size, const char *fmt, va_list ap)
                    __attribute__ ((__format__ (__printf__, 3, 0)));

int puts(const char *str);
int putchar(int c);

#endif /*STDIO_H*/
