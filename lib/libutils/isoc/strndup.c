// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <string.h>

char *strndup(const char *s, size_t n)
{
	size_t l = strnlen(s, n) + 1;
	char *p = malloc(l);

	if (p) {
		memcpy(p, s, l - 1);
		p[l - 1] = '\0';
	}
	return p;
}
