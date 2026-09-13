// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RiscStar
 */

#include <compiler.h>
#include <config.h>
#include <kernel/stack_check.h>
#include <pta_invoke_tests.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "misc.h"

#define SCAN_WORDS	64

static jmp_buf smash_jmp;

static void __noreturn smash_detected(void)
{
	longjmp(smash_jmp, 1);
}

static void __noinline touch(char *buf, size_t len)
{
	memset(buf, 0x5a, len);
}

/* Find this frame's canary slot: first word above @buf holding the guard */
static uintptr_t *__noinline find_canary(char *buf)
{
	uintptr_t *p = (void *)ROUNDUP((vaddr_t)buf, sizeof(uintptr_t));
	size_t n = 0;

	for (n = 0; n < SCAN_WORDS; n++)
		if (p[n] == (uintptr_t)__stack_chk_guard)
			return (uintptr_t *)(p + n);

	return NULL;
}

static bool __noinline frame_has_canary(void)
{
	char buf[16] = { };

	touch(buf, sizeof(buf));

	return !!find_canary(buf);
}

static void __noinline smash_frame(void)
{
	char buf[16] = { };
	uintptr_t *slot = NULL;

	touch(buf, sizeof(buf));

	slot = find_canary(buf);
	if (slot)
		*slot ^= 0x100;
}

/* No local variable may live across setjmp() here, see C11 7.13.2.1 */
static bool smash_is_detected(void)
{
	stack_chk_set_fail_cb(smash_detected);

	if (setjmp(smash_jmp)) {
		stack_chk_set_fail_cb(NULL);
		return true;
	}

	smash_frame();
	stack_chk_set_fail_cb(NULL);
	EMSG("stack smashing not detected");

	return false;
}

TEE_Result core_stack_protector_tests(uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	uintptr_t guard = (uintptr_t)__stack_chk_guard;
	uint32_t flags = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED2(_CFG_CORE_STACK_PROTECTOR))
		flags |= PTA_INVOKE_TESTS_STACK_PROTECTOR_ENABLED;
	/*
	 * A guard supplied by the RNG has its least significant byte
	 * cleared, which the build time default value has not.
	 */
	if (guard && !(guard & 0xff))
		flags |= PTA_INVOKE_TESTS_STACK_PROTECTOR_RANDOMIZED;

	if (flags & PTA_INVOKE_TESTS_STACK_PROTECTOR_ENABLED) {
		if (frame_has_canary())
			flags |= PTA_INVOKE_TESTS_STACK_PROTECTOR_CANARY;

		if (smash_is_detected())
			flags |= PTA_INVOKE_TESTS_STACK_PROTECTOR_DETECTED;
	}

	params[0].value.a = flags;
	params[0].value.b = 0;

	return TEE_SUCCESS;
}
