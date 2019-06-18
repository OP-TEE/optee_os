// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#if defined(__KERNEL__)
#include <platform_config.h>
#include <kernel/misc.h>
#endif

#include <printk.h>
#include <stdarg.h>
#include <string.h>
#include <trace.h>
#include <util.h>
#include <types_ext.h>

#if (TRACE_LEVEL < TRACE_MIN) || (TRACE_LEVEL > TRACE_MAX)
#error "Invalid value of TRACE_LEVEL"
#endif

#if (TRACE_LEVEL >= TRACE_ERROR)

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

static char trace_level_to_string(int level, bool level_ok)
{
	/*
	 * U = Unused
	 * E = Error
	 * I = Information
	 * D = Debug
	 * F = Flow
	 */
	static const char lvl_strs[] = { 'U', 'E', 'I', 'D', 'F' };
	int l = 0;

	if (!level_ok)
		return 'M';

	if ((level >= TRACE_MIN) && (level <= TRACE_MAX))
		l = level;

	return lvl_strs[l];
}

static int print_thread_id(char *buf, size_t bs)
{
#if CFG_NUM_THREADS > 9
	int num_thread_digits = 2;
#else
	int num_thread_digits = 1;
#endif
	int thread_id = trace_ext_get_thread_id();

	if (thread_id >= 0)
		return snprintk(buf, bs, "%0*d ", num_thread_digits, thread_id);
	else
		return snprintk(buf, bs, "%*s ", num_thread_digits, "");
}

#if defined(__KERNEL__)
static int print_core_id(char *buf, size_t bs)
{
#if CFG_TEE_CORE_NB_CORE > 10
	const int num_digits = 2;
#else
	const int num_digits = 1;
#endif

	if (thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR)
		return snprintk(buf, bs, "%0*zu ", num_digits, get_core_pos());
	else
		return snprintk(buf, bs, "%s ", num_digits > 1 ? "??" : "?");
}
#else  /* defined(__KERNEL__) */
static int print_core_id(char *buf __unused, size_t bs __unused)
{
	return 0;
}
#endif

/* Format trace of user ta. Inline with kernel ta */
void trace_printf(const char *function, int line, int level, bool level_ok,
		  const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	trace_vprintf(function, line, level, level_ok, fmt, ap);
	va_end(ap);
}
void trace_vprintf(const char *function, int line, int level, bool level_ok,
		   const char *fmt, va_list ap)
{
	char buf[MAX_PRINT_SIZE];
	size_t boffs = 0;
	int res;

	if (level_ok && level > trace_level)
		return;

	/* Print the type of message */
	res = snprintk(buf, sizeof(buf), "%c/",
		       trace_level_to_string(level, level_ok));
	if (res < 0)
		return;
	boffs += res;

	/* Print the location, i.e., TEE core or TA */
	res = snprintk(buf + boffs, sizeof(buf) - boffs, "%s:",
		       trace_ext_prefix);
	if (res < 0)
		return;
	boffs += res;

	if (level_ok && (BIT(level) & CFG_MSG_LONG_PREFIX_MASK)) {
		/* Print the core ID if in atomic context  */
		res = print_core_id(buf + boffs, sizeof(buf) - boffs);
		if (res < 0)
			return;
		boffs += res;

		/* Print the Thread ID */
		res = print_thread_id(buf + boffs, sizeof(buf) - boffs);
		if (res < 0)
			return;
		boffs += res;

		if (function) {
			res = snprintk(buf + boffs, sizeof(buf) - boffs, "%s:%d ",
				       function, line);
			if (res < 0)
				return;
			boffs += res;
		}
	} else {
		/* Add space after location info */
		if (boffs >= sizeof(buf) - 1)
		    return;
		buf[boffs++] = ' ';
		buf[boffs] = 0;
	}

	res = vsnprintk(buf + boffs, sizeof(buf) - boffs, fmt, ap);
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
