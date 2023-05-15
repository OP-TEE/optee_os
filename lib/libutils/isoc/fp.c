// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */

#include <stdio.h>

struct _FILE {
	char dummy;
};

static struct _FILE _fake_stdout;
static struct _FILE _fake_stderr;

FILE *stdout = &_fake_stdout;
FILE *stderr = &_fake_stderr;
