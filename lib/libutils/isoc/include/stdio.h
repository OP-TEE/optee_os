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

#ifndef __KERNEL__

extern FILE *stdout;
extern FILE *stderr;

/*
 * The functions below send their output synchronously to the secure console.
 * They treat stdout and stderr the same, and will abort if stream is not one or
 * the other.
 */

int fputc(int c, FILE *stream);
int fputs(const char *s, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
#endif

#endif /*STDIO_H*/
