// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
#include <trace.h>

#if defined(__KERNEL__)
# include <kernel/panic.h>
# include <kernel/stack_check.h>
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

#if defined(__KERNEL__) && defined(CFG_TEE_CORE_EMBED_INTERNAL_TESTS)
static stack_chk_fail_cb_t stack_chk_fail_cb __nex_bss;

void stack_chk_set_fail_cb(stack_chk_fail_cb_t cb)
{
	stack_chk_fail_cb = cb;
}

static void stack_chk_test_fail(void)
{
	if (stack_chk_fail_cb)
		stack_chk_fail_cb();
}
#else
static inline void stack_chk_test_fail(void) { }
#endif

void __stack_chk_fail(void)
{
	stack_chk_test_fail();
	EMSG_RAW("stack smashing detected");
	while (1)
		PANIC();
}

