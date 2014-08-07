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

#define STR_TRACE_CORE "TEE-CORE-TZ"
#include <kernel/tee_core_trace.h>

#ifdef WITH_UART_DRV
#include <drivers/uart.h>
#include <plat.h>
#else
#include <kernel/asc.h>
#endif

#if (CFG_TEE_CORE_LOG_LEVEL != 0)

/* Default trace level */
int _trace_level = CFG_TEE_CORE_LOG_LEVEL;


#ifdef WITH_UART_DRV
static void output_string(const char *str)
{
	const char *p = str;

	while (*p) {
		uart_putc(*p, UART1_BASE);
		p++;
	}
}

static void output_flush(void)
{
	uart_flush_tx_fifo(UART1_BASE);
}
#else
#define output_string(x) __asc_xmit(x)
#define output_flush() __asc_flush()
#endif

void core_trace_test(void)
{
	INMSG("level: [%d]", _trace_level);
	IMSG("current trace level = %d", _trace_level);
	IMSG("Without args");
	AMSG("[%d] and [%s]", TRACE_ALWAYS, "TRACE_ALWAYS");
	EMSG("[%d] and [%s]", TRACE_ERROR, "TRACE_ERROR");
	IMSG("[%d] and [%s]", TRACE_INFO, "TRACE_INFO");
	DMSG("[%d] and [%s]", TRACE_DEBUG, "TRACE_DEBUG");
	FMSG("[%d] and [%s]", TRACE_FLOW, "TRACE_FLOW");
	AMSG_RAW("Raw trace in TEE CORE with level [%s]", "TRACE_ALWAYS");
	AMSG_RAW(" __ end of raw trace\n");
	DMSG_RAW("Raw trace in TEE CORE with level [%s]", "TRACE_DEBUG");
	DMSG_RAW(" __ end of raw trace\n");
	OUTMSG("");
}

void set_trace_level(int level)
{
	if (((int)level >= TRACE_MIN) && (level <= TRACE_MAX))
		_trace_level = level;
	else
		AMSG("Can't set level [%d]", level);

	core_trace_test();
	AMSG_RAW("\nLevel set to [%d]\n", _trace_level);
}

int get_trace_level(void)
{
	return _trace_level;
}

static const char const *_trace_level_to_string[] = {
	"NONE", "ALW", "ERR", "INF", "DBG", "FLW" };

/* Format trace of user ta. Inline with kernel ta */
static int format_trace(const char *function, int line, int level,
			const char *prefix, const char *in, char *out)
{
	int nb_char = MAX_PRINT_SIZE;
	const char *func;
	int thread_id = 0;

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
			     _trace_level_to_string[level], thread_id, prefix,
			     func, line, in);
	} else {
		memcpy(out, in, MAX_PRINT_SIZE);

		/* we need to add \n and a \0 at end of the string if not
		 * present. We also set nb_char to the string length, including
		 * appended chars. */
#if (MAX_PRINT_SIZE <= 2)
#error "cannot support MAX_PRINT_SIZE lesser than 3!"
#endif
		nb_char = 0;
		while (*out) {
			out++;
			if (++nb_char == MAX_PRINT_SIZE) {
				/* force the 2 last bytes */
				*(out - 2) = '\n';
				*(out - 1) = '\0';
				return MAX_PRINT_SIZE - 1;
			}
		}
		if (*(out - 1) != '\n') {
			/* force last char to \n and append the \0 */
			*(out) = '\n';
			*(out + 1) = '\0';
			nb_char++;
		}
	}
	return nb_char;
}

int _dprintf(const char *function, int line, int level, const char *prefix,
	     const char *fmt, ...)
{
	char to_format[MAX_PRINT_SIZE];
	char formatted[MAX_PRINT_SIZE];
	va_list ap;
	int nb;

	va_start(ap, fmt);
	(void)vsnprintf(to_format, sizeof(to_format), fmt, ap);
	va_end(ap);

	nb = format_trace(function, line, level, prefix, to_format, formatted);

	/*
	 * dprint is making use of the uart.
	 * a shared mem / circular buffer based trace could be used instead
	 */
	output_string(formatted);

	return nb;
}

int _dprintf_hwsync(const char *function, int line, const char *fmt, ...)
{
	char to_format[MAX_PRINT_SIZE];
	char formatted[MAX_PRINT_SIZE];
	va_list ap;
	int nb;

	va_start(ap, fmt);
	(void)vsnprintf(to_format, sizeof(to_format), fmt, ap);
	va_end(ap);

	nb = format_trace(function, line, TRACE_ALWAYS, "HWSYNC", to_format,
			  formatted);

	/* note: no contention or synchro handle with other CPU core ! */
	output_flush();
	output_string(formatted);
	output_flush();

	return nb;
}

#endif
