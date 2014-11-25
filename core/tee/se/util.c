/*
 * Copyright (c) 2014, Linaro Limited
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

#include <tee_api_types.h>
#include <trace.h>
#include <tee/se/util.h>

#include <stdio.h>

char *print_buf(char *buf, size_t *remain_size, const char *fmt, ...)
{
	va_list ap;
	size_t len;

	va_start(ap, fmt);
	len = vsnprintf(buf, *remain_size, fmt, ap);
	buf += len;
	*remain_size -= len;
	va_end(ap);
	return buf;
}

void dump_hex(char *buf, size_t *remain_size, uint8_t *input_buf,
		size_t input_size)
{
	size_t i;

	for (i = 0; i < input_size; i++)
		buf = print_buf(buf, remain_size, "%02X ", input_buf[i]);
}

void print_hex(uint8_t *input_buf, size_t input_size)
{
	char buf[DUMP_BUF_MAX];
	size_t remain = sizeof(buf);

	dump_hex(buf, &remain, input_buf, input_size);
	DMSG("%s", buf);
}

uint8_t *hex_decode(const char *in, size_t len, uint8_t *out)
{
	size_t i, t, hn, ln;

	for (t = 0, i = 0; i < len; i += 2, ++t) {
		hn = in[i] > '9' ?
			(in[i] | 32) - 'a' + 10 : in[i] - '0';
		ln = in[i + 1] > '9' ?
			(in[i + 1] | 32) - 'a' + 10 : in[i + 1] - '0';

		out[t] = (hn << 4) | ln;
	}
	return out;
}
