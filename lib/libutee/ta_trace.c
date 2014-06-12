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
#if (CFG_TEE_TA_LOG_LEVEL > 0)
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <tee_internal_api_extensions.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include "utee_misc.h"

/*****************************************************************************/

static const char *const trace_level_strings[] = {
	"NONE", "ALW", "ERR", "INF", "DBG", "FLW"
};

static const char failed[] = "uta trace failed";

/*****************************************************************************/

/* Format trace of user ta. Inline with kernel ta */
static int format_trace(const char *function, int line, int level,
			const char *prefix, const char *in, char *out)
{
	const char *func;
	int nb_char = MAX_PRINT_SIZE;

	if (function) {
#ifdef TRACE_FUNC_LENGTH_CST
		char func_buf[MAX_FUNC_PRINT_SIZE];
		int flen = strlen(function);

		/* Limit the function name to MAX_FUNC_PRINT_SIZE characters. */
		strncpy(func_buf, function, flen > MAX_FUNC_PRINT_SIZE ?
			(MAX_FUNC_PRINT_SIZE - 1) : flen);
		if (flen < (MAX_FUNC_PRINT_SIZE - 1)) {
			memset(func_buf + flen, 0x20,
			       (MAX_FUNC_PRINT_SIZE - flen));
		}
		func_buf[MAX_FUNC_PRINT_SIZE - 1] = '\0';
		func = func_buf;
#else
		func = function;
#endif
		nb_char =
		    snprintf(out, MAX_PRINT_SIZE, "%s [%p] %s:%s:%d: %s\n",
			     trace_level_strings[level],
			     (void *)utee_get_ta_exec_id(), prefix, func, line,
			     in);
	} else {
		/* copy buffer and insure '\n' terminated, before '\0' */
		memcpy(out, in, MAX_PRINT_SIZE);
		*(out + MAX_PRINT_SIZE - 1) = '\0';
		nb_char = strlen(out);
		if (nb_char == (MAX_PRINT_SIZE - 2)) {
			*(out + (MAX_PRINT_SIZE - 2)) = '\n';
		} else if (*(out + nb_char - 1) != '\n') {
			*(out + nb_char) = '\n';
			*(out + nb_char + 1) = '\0';
		}
	}
	return nb_char;
}

/* To be call from user side */
int _dprintf_uta(const char *function, int line, int level, const char *prefix,
		 const char *fmt, ...)
{
	char to_format[MAX_PRINT_SIZE];
	char formatted[MAX_PRINT_SIZE];
	char trunc[] = "...\n";
	va_list ap;
	int s;

	va_start(ap, fmt);
	s = vsnprintf(to_format, sizeof(to_format), fmt, ap);
	va_end(ap);

	if (s < 0) {
		utee_log(failed, strlen(failed) + 1);
		return s;
	}
	if (((unsigned int)s >= sizeof(to_format)) &&
	    (MAX_PRINT_SIZE > sizeof(trunc)))
		memcpy(&to_format[sizeof(to_format) - sizeof(trunc)], trunc,
		       sizeof(trunc));

	/* Format trace at user side */
	s = format_trace(function, line, level, prefix, to_format, formatted);

	/* sys call */
	utee_log(formatted, strlen(formatted) + 1);

	return s;
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
	char prefix[] = "[ta log] ";
	char trunc[] = "...\n";
	va_list ap;
	int s;

	if (tahead_get_trace_level() <= TRACE_PRINTF_LEVEL)
		return 0;

	s = snprintf(to_format, sizeof(to_format), "%s", prefix);
	if (s < 0) {
		utee_log(failed, strlen(failed) + 1);
		return s;
	}
	if ((unsigned int)s >= sizeof(to_format)) {
		utee_log(failed, strlen(failed) + 1);
		return 0;
	}

	va_start(ap, fmt);
	s = vsnprintf(to_format + s, sizeof(to_format) - s, fmt, ap);
	va_end(ap);

	if (s < 0) {
		utee_log(failed, strlen(failed) + 1);
		return s;
	}
	if (((unsigned int)s >= (sizeof(to_format) - strlen(prefix)))) {
		memcpy(&to_format[sizeof(to_format) - sizeof(trunc)], trunc,
		       sizeof(trunc));
		s = sizeof(to_format) - sizeof(prefix) - sizeof(trunc);
	}

	/* sys call */
	utee_log(to_format, strlen(to_format) + 1);

	return s;
}

int puts(const char *str)
{
	return printf("%s", str);
}

#else /* CFG_TEE_TA_LOG_LEVEL */
#include <tee_internal_api_extensions.h>
int printf(const char *fmt, ...)
{
	return 0;
}

int puts(const char *str)
{
	return 0;
}
#endif /* CFG_TEE_TA_LOG_LEVEL */
