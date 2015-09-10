/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>
#include <utee_syscalls.h>

#if TRACE_LEVEL > 0

void trace_ext_puts(const char *str)
{
	utee_log(str, strlen(str));
}

int trace_ext_get_thread_id(void)
{
	return -1;
}


/*
 * printf and puts - stdio printf support
 *
 * 'printf()' and 'puts()' traces have the 'info' trace level.
 * Traces are prefixed with string "[ta log] ".
 */
int printf(const char *fmt, ...)
{
	char to_format[MAX_PRINT_SIZE];
	static const char prefix[] = "[ta log] ";
	static const char failed[] = "uta trace failed";
	static const char trunc[] = "...\n";
	va_list ap;
	int s;

	if (trace_get_level() < TRACE_PRINTF_LEVEL)
		return 0;

	s = strlcpy(to_format, prefix, sizeof(to_format));
	if ((unsigned int)s >= sizeof(to_format)) {
		puts(failed);
		return 0;
	}

	va_start(ap, fmt);
	s = vsnprintf(to_format + s, sizeof(to_format) - s, fmt, ap);
	va_end(ap);

	if (s < 0) {
		puts(failed);
		return s;
	}
	if (((unsigned int)s >= (sizeof(to_format) - strlen(prefix)))) {
		memcpy(&to_format[sizeof(to_format) - sizeof(trunc)], trunc,
		       sizeof(trunc));
		s = sizeof(to_format) - sizeof(prefix) - sizeof(trunc);
	}

	puts(to_format);

	return s;
}

int puts(const char *str)
{
	if (trace_get_level() >= TRACE_PRINTF_LEVEL)
		trace_ext_puts(str);
	return 1;
}

#else

int printf(const char *fmt __unused, ...)
{
	return 0;
}

int puts(const char *str __unused)
{
	return 0;
}

#endif
