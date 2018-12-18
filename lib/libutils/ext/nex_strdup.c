// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018 EPAM Systems
 */
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>

char *nex_strdup(const char *s)
{
	size_t l = strlen(s) + 1;
	char *p = nex_malloc(l);

	if (p)
		memcpy(p, s, l);
	return p;
}
