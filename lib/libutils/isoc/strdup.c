// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <string.h>

char *strdup(const char *s)
{
	size_t l = strlen(s) + 1;
	char *p = malloc(l);

	if (p)
		memcpy(p, s, l);
	return p;
}
