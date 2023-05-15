// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <stdio.h>
#include <tee_api.h>
#include <compiler.h>
#include <utee_syscalls.h>

void abort(void)
{
	printf("Abort!\n");
	_utee_panic(0);
	/* Not reached */
	while (1)
		;
}
