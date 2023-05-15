// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "base64.h"

static const char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t _base64_enc_len(size_t size)
{
	return 4 * ((size + 2) / 3) + 1;
}

bool _base64_enc(const void *data, size_t dlen, char *buf, size_t *blen)
{
	size_t n = 0;
	size_t boffs = 0;
	const unsigned char *d = data;

	n = _base64_enc_len(dlen);
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
	size_t n = 0;

	for (n = 0; base64_table[n] != '\0'; n++) {
		if (ch == base64_table[n]) {
			*idx = n;
			return true;
		}
	}
	return false;
}

bool _base64_dec(const char *data, size_t size, void *buf, size_t *blen)
{
	bool ret = false;
	size_t n = 0;
	uint8_t idx = 0;
	uint8_t *b = buf;
	size_t m = 0;
	size_t s = 0;
	uint8_t byte = 0;

	for (n = 0; n < size && data[n] != '\0'; n++) {
		if (data[n] == '=')
			break;	/* Reached pad characters, we're done */

		if (!get_idx(data[n], &idx))
			continue;

		switch (s) {
		case 0:
			byte = idx << 2;
			s++;
			break;
		case 1:
			if (b && m < *blen)
				b[m] = byte | (idx >> 4);
			m++;
			byte = (idx & 0xf) << 4;
			s++;
			break;
		case 2:
			if (b && m < *blen)
				b[m] = byte | (idx >> 2);
			m++;
			byte = (idx & 0x3) << 6;
			s++;
			break;
		case 3:
			if (b && m < *blen)
				b[m] = byte | idx;
			m++;
			s = 0;
			break;
		default:
			return false;	/* "Can't happen" */
		}
	}

	/*
	 * We don't detect if input was bad, but that's OK with the spec.
	 * We expect that each fully extracted byte is stored in output buffer.
	 */
	ret = (!m && !*blen) || (b && (m <= *blen));
	*blen = m;

	return ret;
}
