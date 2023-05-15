// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>

static int hex(char c)
{
	char lc = tolower(c);

	if (isdigit(lc))
		return lc - '0';
	if (isxdigit(lc))
		return lc - 'a' + 10;
	return -1;
}

static uint32_t parse_hex(const char *s, size_t nchars, uint32_t *res)
{
	uint32_t v = 0;
	size_t n = 0;
	int c = 0;

	for (n = 0; n < nchars; n++) {
		c = hex(s[n]);
		if (c == -1) {
			*res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
		v = (v << 4) + c;
	}
	*res = TEE_SUCCESS;
out:
	return v;
}

TEE_Result tee_uuid_from_str(TEE_UUID *uuid, const char *s)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_UUID u = { };
	const char *p = s;
	size_t i = 0;

	if (!p || strnlen(p, 37) != 36)
		return TEE_ERROR_BAD_FORMAT;
	if (p[8] != '-' || p[13] != '-' || p[18] != '-' || p[23] != '-')
		return TEE_ERROR_BAD_FORMAT;

	u.timeLow = parse_hex(p, 8, &res);
	if (res)
		goto out;
	p += 9;
	u.timeMid = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	u.timeHiAndVersion = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	for (i = 0; i < 8; i++) {
		u.clockSeqAndNode[i] = parse_hex(p, 2, &res);
		if (res)
			goto out;
		if (i == 1)
			p += 3;
		else
			p += 2;
	}
	*uuid = u;
out:
	return res;
}
