// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */
#include <string_ext.h>

int buf_compare_ct(const void *s1, const void *s2, size_t n)
{
	int res = 0;
	unsigned char *c1 = (unsigned char *)s1;
	unsigned char *c2 = (unsigned char *)s2;

	while (n--) {
		res |= (*c1 ^ *c2);
		c1++;
		c2++;
	}

	res |= res >> 4;
	res |= res >> 2;
	res |= res >> 1;
	res &= 1;

	return res;
}
