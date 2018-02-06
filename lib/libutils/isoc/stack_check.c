// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
void *__stack_chk_guard __nex_data = (void *)0x00000aff;

void __attribute__((noreturn)) __stack_chk_fail(void);

void __stack_chk_fail(void)
{
	while (1)
		;
}

