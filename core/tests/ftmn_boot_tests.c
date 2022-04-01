// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <assert.h>
#include <fault_mitigation.h>
#include <initcall.h>
#include <kernel/thread.h>
#include <trace.h>
#include <types_ext.h>

/*
 * Simple straightforward tests.
 */
static TEE_Result simple_call_func_res;

static TEE_Result __noinline simple_call_func1(void)
{
	TEE_Result res = simple_call_func_res;

	FTMN_CALLEE_DONE(res);
	return res;
}

static TEE_Result __noinline simple_call_memcmp(const void *s1, const void *s2,
						size_t n)
{
	if (!FTMN_CALLEE_DONE_MEMCMP(memcmp, s1, s2, n))
		return TEE_SUCCESS;
	return TEE_ERROR_GENERIC;
}

static void __noinline simple_call(void)
{
	TEE_Result res = TEE_SUCCESS;
	struct ftmn ftmn = { };
	static const char s1[] = "s1";

	simple_call_func_res = TEE_SUCCESS;
	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0, simple_call_func1);
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(1), res);

	simple_call_func_res = TEE_ERROR_GENERIC;
	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0, simple_call_func1);
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(2, 1), res);

	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
		       simple_call_memcmp, s1, s1, sizeof(s1));
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(3, 2), res);
}

/*
 * Simulate calling with multiple unmitigated functions in the chain
 * between checked callee and the caller. The result has always been set
 * regardless of return value.
 */

static TEE_Result __noinline two_level_call_memcmp2(const void *s1,
						    const void *s2, size_t n)
{
	if (!FTMN_CALLEE_DONE_MEMCMP(memcmp, s1, s2, n))
		return TEE_SUCCESS;
	/*
	 * If FTMN_CALLEE_DONE_MEMCMP() returned non-zero the strings are
	 * different. Update with an error code we can understand.
	 */
	FTMN_CALLEE_UPDATE_NOT_ZERO(TEE_ERROR_GENERIC);
	return TEE_ERROR_GENERIC;
}

static TEE_Result __noinline two_level_call_memcmp1(const void *s1,
						    const void *s2, size_t n)
{
	return two_level_call_memcmp2(s1, s2, n);
}

static TEE_Result __noinline two_level_call_memcmp(const void *s1,
						   const void *s2, size_t n)
{
	unsigned long func_hash = FTMN_FUNC_HASH("two_level_call_memcmp2");
	struct ftmn ftmn = { };
	TEE_Result res = TEE_SUCCESS;

	FTMN_PUSH_LINKED_CALL(&ftmn, func_hash);
	res = two_level_call_memcmp1(s1, s2, n);
	FTMN_SET_CHECK_RES_FROM_CALL(&ftmn, 0, res);
	FTMN_POP_LINKED_CALL(&ftmn);
	FTMN_CALLEE_DONE_CHECK(&ftmn, FTMN_INCR1, 0, res);

	return res;
}

static void __noinline two_level_call(void)
{
	struct ftmn ftmn = { };
	TEE_Result res = TEE_SUCCESS;
	static const char s1[] = "s1";
	static const char s2[] = "s2";

	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
		       two_level_call_memcmp, s1, s1, sizeof(s1));
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(1), res);

	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
		       two_level_call_memcmp, s1, s2, sizeof(s1));
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(2, 1), res);
}

/*
 * Simulate chained calls in several levels.
 *
 * For instance ree_fs_ta_open() -> shdr_verify_signature() ->
 * crypto_acipher_rsassa_verify() -> ... ->
 * mbedtls_rsa_rsassa_pss_verify_ext()
 */

static TEE_Result __noinline chained_call_memcmp2(const void *s1,
						  const void *s2, size_t n)
{
	if (!FTMN_CALLEE_DONE_MEMCMP(memcmp, s1, s2, n))
		return TEE_SUCCESS;
	return TEE_ERROR_GENERIC;
}

static TEE_Result __noinline chained_call_memcmp1(const void *s1,
						  const void *s2, size_t n)
{
	TEE_Result res = chained_call_memcmp2(s1, s2, n);

	/*
	 * If s1 and s2 has the same content but different pointers we're
	 * testing the case with an error detected after the linked leaf
	 * function has been called.
	 */
	if (!res && s1 != s2)
		res = TEE_ERROR_BAD_STATE;

	return res;
}

static TEE_Result __noinline chained_call_memcmp(const void *s1,
						 const void *s2, size_t n)
{
	struct ftmn ftmn = { };
	TEE_Result res = TEE_SUCCESS;

	FTMN_PUSH_LINKED_CALL(&ftmn, FTMN_FUNC_HASH("chained_call_memcmp2"));

	res = chained_call_memcmp1(s1, s2, n);

	if (!res)
		FTMN_SET_CHECK_RES_FROM_CALL(&ftmn, FTMN_INCR0, res);
	else
		FTMN_SET_CHECK_RES(&ftmn, FTMN_INCR0, res);
	FTMN_POP_LINKED_CALL(&ftmn);
	FTMN_CALLEE_DONE_CHECK(&ftmn, FTMN_INCR0, FTMN_STEP_COUNT(1), res);

	return res;
}

static void __noinline chained_calls(void)
{
	struct ftmn ftmn = { };
	static const char s[] = "s1s2s1";
	TEE_Result res = TEE_SUCCESS;

	/* Test a normal success case. */
	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0, chained_call_memcmp, s, s, 2);
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(1), res);

	/* Test the case where the leaf function detects an error. */
	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
		       chained_call_memcmp, s, s + 2, 2);
	assert(res == TEE_ERROR_GENERIC);
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(2, 1),
			  TEE_ERROR_GENERIC);

	/*
	 * Test the case where a function in the call chain detects an error
	 * after a the leaf function has returned success.
	 */
	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
		       chained_call_memcmp, s, s + 4, 2);
	assert(res == TEE_ERROR_BAD_STATE);
	ftmn_expect_state(&ftmn, FTMN_INCR1, FTMN_STEP_COUNT(3, 2),
			  TEE_ERROR_BAD_STATE);
}

#define CALL_TEST_FUNC(x) do { \
		DMSG("Calling " #x "()"); \
		x(); \
		DMSG("Return from " #x "()"); \
	} while (0)

static TEE_Result ftmn_boot_tests(void)
{
	CALL_TEST_FUNC(simple_call);
	CALL_TEST_FUNC(two_level_call);
	CALL_TEST_FUNC(chained_calls);

	DMSG("*************************************************");
	DMSG("**************  Tests complete  *****************");
	DMSG("*************************************************");
	return TEE_SUCCESS;
}

driver_init_late(ftmn_boot_tests);
