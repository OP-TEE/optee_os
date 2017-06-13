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

#include <printk.h>
#include <stdarg.h>
#include <string.h>
#include <trace.h>
#include <util.h>
#include <types_ext.h>

#if (TRACE_LEVEL > 0)

#if (TRACE_LEVEL < TRACE_MIN) || (TRACE_LEVEL > TRACE_MAX)
#error "Invalid value of TRACE_LEVEL"
#endif

void trace_set_level(int level)
{
	if (((int)level >= TRACE_MIN) && (level <= TRACE_MAX))
		trace_level = level;
	else
		trace_level = TRACE_MAX;
}

int trace_get_level(void)
{
	return trace_level;
}

static const char *trace_level_to_string(int level, bool level_ok)
{
	static const char lvl_strs[][9] = {
		"UNKNOWN:", "ERROR:  ", "INFO:   ", "DEBUG:  ",
		"FLOW:   " };
	int l = 0;

	if (!level_ok)
		return "MESSAGE:";

	if ((level >= TRACE_MIN) && (level <= TRACE_MAX))
		l = level;

	return lvl_strs[l];
}

/* Format trace of user ta. Inline with kernel ta */
void trace_printf(const char *function, int line, int level, bool level_ok,
		  const char *fmt, ...)
{
	va_list ap;
	char buf[MAX_PRINT_SIZE];
	size_t boffs = 0;
	int res;
	int thread_id;

	if (level_ok && level > trace_level)
		return;

	res = snprintk(buf, sizeof(buf), "%s ",
		       trace_level_to_string(level, level_ok));
	if (res < 0)
		return;
	boffs += res;

	if (level_ok && !(BIT(level) & CFG_MSG_LONG_PREFIX_MASK))
		thread_id = -1;
	else
		thread_id = trace_ext_get_thread_id();

	if (thread_id >= 0) {
		res = snprintk(buf + boffs, sizeof(buf) - boffs, "[0x%x] ",
			       thread_id);
		if (res < 0)
			return;
		boffs += res;
	}

	res = snprintk(buf + boffs, sizeof(buf) - boffs, "%s:",
		       trace_ext_prefix);
	if (res < 0)
		return;
	boffs += res;

	if (level_ok && !(BIT(level) & CFG_MSG_LONG_PREFIX_MASK))
		function = NULL;

	if (function) {
		res = snprintk(buf + boffs, sizeof(buf) - boffs, "%s:%d:",
			       function, line);
		if (res < 0)
			return;
		boffs += res;
	}

	res = snprintk(buf + boffs, sizeof(buf) - boffs, " ");
	if (res < 0)
		return;
	boffs += res;

	va_start(ap, fmt);
	res = vsnprintk(buf + boffs, sizeof(buf) - boffs, fmt, ap);
	va_end(ap);
	if (res > 0)
		boffs += res;

	if (boffs >= (sizeof(buf) - 1))
		boffs = sizeof(buf) - 2;

	buf[boffs] = '\n';
	while (boffs && buf[boffs] == '\n')
		boffs--;
	boffs++;
	buf[boffs + 1] = '\0';

	trace_ext_puts(buf);
}

#else

/*
 * In case we have a zero or negative trace level when compiling optee_os, we
 * have to add stubs to trace functions in case they are used with TA having a
 * non-zero trace level
 */

void trace_set_level(int level __unused)
{
}

int trace_get_level(void)
{
	return 0;
}

void trace_printf(const char *function __unused, int line __unused,
		  int level __unused, bool level_ok __unused,
		  const char *fmt __unused, ...)
{
}

#endif

#if (TRACE_LEVEL >= TRACE_DEBUG)
struct strbuf {
	char buf[MAX_PRINT_SIZE];
	char *ptr;
};

static int __printf(2, 3) append(struct strbuf *sbuf, const char *fmt, ...)
{
	int left;
	int len;
	va_list ap;

	if (sbuf->ptr == NULL)
		sbuf->ptr = sbuf->buf;
	left = sizeof(sbuf->buf) - (sbuf->ptr - sbuf->buf);
	va_start(ap, fmt);
	len = vsnprintk(sbuf->ptr, left, fmt, ap);
	va_end(ap);
	if (len < 0) {
		/* Format error */
		return 0;
	}
	if (len >= left) {
		/* Output was truncated */
		return 0;
	}
	sbuf->ptr += MIN(left, len);
	return 1;
}

#define PRIxVA_WIDTH ((int)(sizeof(vaddr_t)*2))

void dhex_dump(const char *function, int line, int level,
	       const void *buf, int len)
{
	int i;
	int ok;
	struct strbuf sbuf;
	char *in = (char *)buf;

	if (level <= trace_level) {
		sbuf.ptr = NULL;
		for (i = 0; i < len; i++) {
			if ((i % 16) == 0) {
				ok = append(&sbuf, "%0*" PRIxVA "  ",
					    PRIxVA_WIDTH, (vaddr_t)(in + i));
				if (!ok)
					goto err;
			}
			ok = append(&sbuf, "%02x ", in[i]);
			if (!ok)
				goto err;
			if ((i % 16) == 7) {
				ok = append(&sbuf, " ");
				if (!ok)
					goto err;
			} else if ((i % 16) == 15) {
				trace_printf(function, line, level, true, "%s",
					     sbuf.buf);
				sbuf.ptr = NULL;
			}
		}
		if (sbuf.ptr) {
			/* Buffer is not empty: flush it */
			trace_printf(function, line, level, true, "%s",
				     sbuf.buf);

		}
	}
	return;
err:
	DMSG("Hex dump error");
}
#else

/*
 * In case we have trace level less than debug when compiling optee_os, we have
 * to add stubs to trace functions in case they are used with TA having a
 * a higher trace level
 */

void dhex_dump(const char *function __unused, int line __unused,
	       int level __unused,
	       const void *buf __unused, int len __unused)
{
}

#endif
