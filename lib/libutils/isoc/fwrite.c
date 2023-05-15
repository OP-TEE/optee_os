// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	int fd = 0;

	if (stream == stdout)
		fd = 1;
	else if (stream == stderr)
		fd = 2;
	else
		abort();

	return write(fd, ptr, size * nmemb);
}
