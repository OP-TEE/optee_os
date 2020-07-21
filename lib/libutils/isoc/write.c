// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t count)
{
	if (fd != 1 && fd != 2)
		abort();

	return printf("%*s", (int)count, (char *)buf);
}
