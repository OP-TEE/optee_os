// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 *
 * OP-TEE implementation for undefined SE050 middleware symbols
 */

#include <fsl_sss_api.h>
#include <kernel/delay.h>
#include <nxLog.h>
#include <printk.h>
#include <trace.h>
#include <wraps.h>

struct strbuf {
	char buf[MAX_PRINT_SIZE];
	char *ptr;
};

#define MIN(a, b)				\
(__extension__({ __typeof__(a) _a = (a);	\
__typeof__(b) _b = (b);				\
_a < _b ? _a : _b; }))

static unsigned long next = 1;

sss_status_t sm_sleep(uint32_t ms)
{
	mdelay(ms);

	return kStatus_SSS_Success;
}

int rand(void)
{
	next = next * 1103515245L + 12345;

	return (unsigned int)(next / 65536L) % 32768L;
}

void srand(unsigned int seed)
{
	next = seed;
}

unsigned int time(void *foo __unused)
{
	static int time = 1;

	return time++;
}

void nLog(const char *subsystem, int level, const char *fmt, ...)
{
	char buf[MAX_PRINT_SIZE] = { 0 };
	size_t boffs = 0;
	int res = 0;
	va_list ap = { 0 };

	/*
	 * _extremely_ verbose due to and incorrect WARNING in
	 * sss_user_impl_symmetric_context_free;
	 *
	 */
	if (level < NX_LEVEL_ERROR && level != 0xff)
		return;

	va_start(ap, fmt);
	res = snprintk(buf + boffs, sizeof(buf) - boffs,
		       level != 0xff ? "E/TC: se050: %s: " : "I/TC: se050: %s: "
		       , subsystem);
	if (res < 0)
		return;
	boffs += res;

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
	va_end(ap);
}

static int __printf(2, 3) append(struct strbuf *sbuf, const char *fmt, ...)
{
	int left = 0;
	int len = 0;
	va_list ap = { 0 };

	if (!sbuf->ptr)
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

void nLog_au8(const char *subsystem, int level, const char *message,
	      const unsigned char *buf, size_t len)
{
	size_t i = 0;
	int ok = 0;
	struct strbuf sbuf = { 0 };
	char *in = (char *)buf;

	if (level < NX_LEVEL_ERROR && level != 0xff)
		return;

	nLog(subsystem, level, message);

	sbuf.ptr = NULL;
	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			ok = append(&sbuf, "\t");
			if (!ok)
				goto err;
		}
		ok = append(&sbuf, "%02x", in[i]);
		if (!ok)
			goto err;
		if ((i % 16) == 7) {
			ok = append(&sbuf, " ");
			if (!ok)
				goto err;
		} else if ((i % 16) == 15) {
			nLog(subsystem, level, "%s", sbuf.buf);
			sbuf.ptr = NULL;
		} else {
			if (i + 1 < len) {
				ok = append(&sbuf, ".");
				if (!ok)
					goto err;
			}
		}
	}

	if (sbuf.ptr) {
		/* Buffer is not empty: flush it */
		nLog(subsystem, level, "%s", sbuf.buf);
	}

	return;
err:
	DMSG("Hex dump error");
}
