// SPDX-License-Identifier: BSD-2-Clause
#include <stdlib.h>
#include <string.h>

char *strtok(char *str, const char *delims)
{
	static char *pos = NULL;
	char *start = NULL;

	if (str)
		pos = str;

	if (pos) {
		while (*pos && strchr(delims, *pos)) {
                    pos++;
		}

		if (*pos) {
			start = pos;
			while (*pos && !strchr(delims, *pos)) {
				pos++;
			}

			if (*pos)
				*pos++ = '\0';
		}
	}

	return start;
}
