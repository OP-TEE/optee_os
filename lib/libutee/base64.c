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
#include "base64.h"

static const char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_enc_len(size_t size)
{
	return 4 * ((size + 2) / 3) + 1;
}

bool base64_enc(const void *data, size_t dlen, char *buf, size_t *blen)
{
	size_t n;
	size_t boffs = 0;
	const char *d = data;

	n = base64_enc_len(dlen);
	if (*blen < n) {
		*blen = n;
		return false;
	}

	for (n = 0; n < dlen; n += 3) {
		uint32_t igrp;

		igrp = d[n];
		igrp <<= 8;

		if ((n + 1) < dlen)
			igrp |= d[n + 1];
		igrp <<= 8;

		if ((n + 2) < dlen)
			igrp |= d[n + 2];

		buf[boffs] = base64_table[(igrp >> 18) & 0x3f];
		buf[boffs + 1] = base64_table[(igrp >> 12) & 0x3f];
		if ((n + 1) < dlen)
			buf[boffs + 2] = base64_table[(igrp >> 6) & 0x3f];
		else
			buf[boffs + 2] = '=';
		if ((n + 2) < dlen)
			buf[boffs + 3] = base64_table[igrp & 0x3f];
		else
			buf[boffs + 3] = '=';

		boffs += 4;
	}
	buf[boffs++] = '\0';

	*blen = boffs;
	return true;
}

static bool get_idx(char ch, uint8_t *idx)
{
	size_t n;

	for (n = 0; base64_table[n] != '\0'; n++) {
		if (ch == base64_table[n]) {
			*idx = n;
			return true;
		}
	}
	return false;
}

bool base64_dec(const char *data, size_t size, void *buf, size_t *blen)
{
	size_t n;
	uint8_t idx;
	uint8_t *b = buf;
	size_t m = 0;
	size_t s = 0;

	for (n = 0; n < size && data[n] != '\0'; n++) {
		if (data[n] == '=')
			break;	/* Reached pad characters, we're done */

		if (!get_idx(data[n], &idx))
			continue;

		if (m > *blen)
			b = NULL;

		switch (s) {
		case 0:
			if (b)
				b[m] = idx << 2;
			s++;
			break;
		case 1:
			if (b)
				b[m] |= idx >> 4;
			m++;
			if (m > *blen)
				b = NULL;
			if (b)
				b[m] = (idx & 0xf) << 4;
			s++;
			break;
		case 2:
			if (b)
				b[m] |= idx >> 2;
			m++;
			if (m > *blen)
				b = NULL;
			if (b)
				b[m] = (idx & 0x3) << 6;
			s++;
			break;
		case 3:
			if (b)
				b[m] |= idx;
			m++;
			s = 0;
			break;
		default:
			return false;	/* "Can't happen" */
		}
	}
	/* We don't detect if input was bad, but that's OK with the spec. */
	*blen = m;
	if (b)
		return true;
	else
		return false;
}
