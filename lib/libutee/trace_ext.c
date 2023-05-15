// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Arm Limited
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>
#include <utee_syscalls.h>

#ifdef __LDELF__
#include <ldelf_syscalls.h>
#endif

#if TRACE_LEVEL > 0

void trace_ext_puts(const char *str)
{
#ifdef __LDELF__
	_ldelf_log(str, strlen(str));
#else
	_utee_log(str, strlen(str));
#endif
}

int trace_ext_get_thread_id(void)
{
	return -1;
}

/*
 * printf and puts - stdio printf support
 *
 * 'printf()' and 'puts()' traces have the 'info' trace level.
 */
int printf(const char *fmt, ...)
{
	char to_format[MAX_PRINT_SIZE];
	va_list ap;
	int s;

	if (trace_get_level() < TRACE_PRINTF_LEVEL)
		return 0;

	va_start(ap, fmt);
	s = vsnprintf(to_format, sizeof(to_format), fmt, ap);
	va_end(ap);

	if (s < 0)
		return s;

	trace_ext_puts(to_format);

	return s;
}

int puts(const char *str)
{
	if (trace_get_level() >= TRACE_PRINTF_LEVEL) {
		trace_ext_puts(str);
		trace_ext_puts("\n");
	}
	return 1;
}

int putchar(int c)
{
	char str[2] = { (char)c, '\0' };

	if (trace_get_level() >= TRACE_PRINTF_LEVEL)
		trace_ext_puts(str);
	/*
	 * From the putchar() man page:
	 * "fputc(), putc() and putchar() return the character written as an
	 * unsigned char cast to an int or EOF on error."
	 */
	return (int)(unsigned char)c;
}

#else

void trace_ext_puts(const char *str __unused)
{
}

int printf(const char *fmt __unused, ...)
{
	return 0;
}

int puts(const char *str __unused)
{
	return 0;
}

int putchar(int c)
{
	return (int)(unsigned char)c;
}

#endif
