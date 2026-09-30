// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#include <compiler.h>
#include <config.h>
#include <crypto/crypto.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/stack_check.h>
#include <pta_invoke_tests.h>
#include <setjmp.h>
#include <stdint.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "misc.h"

#define SCAN_WORDS	64

/*
 * setjmp() and longjmp() in the core need ftrace_setjmp() and
 * ftrace_longjmp(), which libutils only builds for user TAs, so the
 * recovery this test relies on cannot be linked when ftrace is enabled.
 */
#ifndef CFG_FTRACE_SUPPORT
static jmp_buf smash_jmp;

static void __noreturn smash_detected(void)
{
	longjmp(smash_jmp, 1);
}
#endif /*!CFG_FTRACE_SUPPORT*/

/*
 * Keep the buffer alive and the frame instrumented.
 *
 * A canary is only emitted for a frame the compiler believes holds a
 * vulnerable object, and the compiler may delete a local array whose
 * contents it can prove are never observed. Either would remove the
 * canary this test looks for, leaving a test that passes against an
 * uninstrumented frame and proves nothing.
 *
 * __noinline alone is not enough to rely on: inter-procedural analysis
 * is free to notice that a memset() of a dead buffer has no observable
 * effect and drop it. Fill the buffer from the RNG instead, so the
 * contents cannot be predicted or constant folded, and store one byte
 * of the result to a sink with io_write8() so the write has an
 * observable side effect that must be kept.
 */
static uint8_t stack_sink;

static void __noinline touch(void *buf, size_t len)
{
	if (crypto_rng_read(buf, len))
		panic("Cannot fill stack protector test buffer");

	io_write8((vaddr_t)&stack_sink, ((uint8_t *)buf)[len - 1]);
}

/* Find this frame's canary slot: first word above @buf holding the guard */
static uintptr_t *__noinline find_canary(void *buf)
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
	uint8_t buf[16] = { };

	touch(buf, sizeof(buf));

	return !!find_canary(buf);
}

#ifndef CFG_FTRACE_SUPPORT
static void __noinline smash_frame(void)
{
	uint8_t buf[16] = { };
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

/*
 * setjmp() saves the callee-saved floating-point registers, which the core
 * traps, so enable them around the call.
 */
static bool smash_is_detected_with_fp(void)
{
	bool detected = false;
#ifdef CFG_WITH_VFP
	uint32_t vfp_state = thread_kernel_enable_vfp();

	detected = smash_is_detected();
	thread_kernel_disable_vfp(vfp_state);
#else
	detected = smash_is_detected();
#endif

	return detected;
}
#endif /*!CFG_FTRACE_SUPPORT*/

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

#ifndef CFG_FTRACE_SUPPORT
		if (smash_is_detected_with_fp())
			flags |= PTA_INVOKE_TESTS_STACK_PROTECTOR_DETECTED;
#endif
	}

	params[0].value.a = flags;
	params[0].value.b = 0;

	return TEE_SUCCESS;
}
