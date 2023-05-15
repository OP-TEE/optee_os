// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
#include <trace.h>

#if defined(__KERNEL__)
# include <kernel/panic.h>
# define PANIC() panic()
#elif defined(__LDELF__)
# include <ldelf_syscalls.h>
# define PANIC() _ldelf_panic(2)
#else
# include <utee_syscalls.h>
# define PANIC() _utee_panic(TEE_ERROR_OVERFLOW)
#endif

void *__stack_chk_guard __nex_data = (void *)0x00000aff;

void __attribute__((noreturn)) __stack_chk_fail(void);

void __stack_chk_fail(void)
{
	EMSG_RAW("stack smashing detected");
	while (1)
		PANIC();
}

