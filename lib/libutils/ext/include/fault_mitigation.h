/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */
#ifndef __FAULT_MITIGATION_H
#define __FAULT_MITIGATION_H

#include <config.h>
#ifdef __KERNEL__
#include <kernel/panic.h>
#include <io.h>
#else
#include <compiler.h>
#include <tee_api.h>

#define READ_ONCE(p)		__compiler_atomic_load(&(p))
#define WRITE_ONCE(p, v)	__compiler_atomic_store(&(p), (v))
#endif

/*
 * Fault migitigation helpers to make successful Hardware Fault Attacks
 * harder to achieve. The paper [1] by Riscure gives background to the
 * problem.
 *
 * Sensitive function can use these helpers to add an extra layer of
 * protection as in this simple example:
 *
 * // This function must only return 0 on success anything else is a failure
 * uint32_t sensitive_function(void)
 * {
 *	struct ftmn_check chk = { };
 *	uint32_t res = 0;
 *	uint32_t value = 0;
 *
 *	// if read_some_value() fails it returns a non-zero value
 *	res = read_some_value(&value);
 *
 *	// First we check the return value and if OK check it again
 *	// with ftmn_check() which will increas and internal counter and
 *	// return true if OK
 *	if (res || !ftmn_check(&chk, FTMN_INCR0, res))
 *		goto out;
 *
 *	// Again, first check that we have the expected value then
 *	// check it again with ftmn_exp_res_check().
 *	if (value != 42 || !ftmn_exp_res_check(&chk, FTMN_INCR1, 42, value))
 *		res = 0xffffff01;
 *
 * out:
 *	// If res is 0 ftmn_final() checks that the two functions ftmn_check()
 *	// and ftmn_exp_res_check() has succeeded with help of the constant
 *	// provided by FTMN_STEP_COUNT2(). If the numbers doesn't add up
 *	// 0xffffff02 will be returned instead.
 *	return ftmn_final(0xffffff02, &chk, FTMN_STEP_COUNT2(1, 1), res);
 * }
 *
 * With this pattern applied an attacker will need to do at least a double
 * glitch (glitch at least one instruction, execute some instructions, and
 * glitch at least one more instruction) while this function or one of the
 * ftmn_*() functions are executed.
 *
 * [1] https://www.riscure.com/uploads/2020/05/Riscure_Whitepaper_Fault_Mitigation_Patterns_final.pdf
 */

#include <stdint.h>
#include <stdbool.h>

struct ftmn_check {
	unsigned long steps;
	unsigned long val;
};

struct ftmn_func_arg {
	unsigned long hash;
	unsigned long ret;
};

enum ftmn_incr {
	FTMN_INCR0 = 7873,
	FTMN_INCR1 = 7877,
	FTMN_INCR2 = 7879,
	FTMN_INCR3 = 7883,
	FTMN_INCR4 = 7901,
	FTMN_INCR5 = 7907,
	FTMN_INCR_RESERVED = 7919,
};

#ifdef __ILP32__
#define FTMN_DEFAULT_HASH	0x9c478bf6UL
#else
#define FTMN_DEFAULT_HASH	0xc478bf63e9500cb5UL
#endif
/*
 * Function names are "hashed" into an unsigned long. The "hashing" is done
 * by xoring each 32/64 bit word of the function name producing a bit
 * pattern that should be mostly unique for each function. Only the first
 * 256 characters of the name are used when xoring as this is expected to
 * be optimized to be calculated when compiling the source code in order to
 * minimize the overhead.
 */
#define __FTMN_MAX_FUNC_LEN	256

#define __FUNC_BYTE(f, o, l)	((o) < (l) ? (uint8_t)(f)[(o)] : 0)

#define __FTMN_GET_FUNC_U64(f, o, l) \
	(SHIFT_U64(__FUNC_BYTE((f), (o), (l)), 0) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 1, (l)), 8) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 2, (l)), 16) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 3, (l)), 24) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 4, (l)), 32) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 5, (l)), 40) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 6, (l)), 48) | \
	 SHIFT_U64(__FUNC_BYTE((f), (o) + 7, (l)), 56))

#define __FUNC_HASH32(f, o, l) \
	(__FTMN_GET_FUNC_U64((f), (o), (l)) ^ \
	 __FTMN_GET_FUNC_U64((f), (o) + 8, (l)))

#define __FUNC_HASH16(f, o, l) \
	(__FUNC_HASH32((f), (o), (l)) ^ \
	 __FUNC_HASH32((f), (o) + __FTMN_MAX_FUNC_LEN / 16, (l)))

#define __FUNC_HASH8(f, o, l) \
	(__FUNC_HASH16((f), (o), (l)) ^ \
	 __FUNC_HASH16((f), (o) + __FTMN_MAX_FUNC_LEN / 8, (l)))

#define __FUNC_HASH4(f, o, l) \
	(__FUNC_HASH8((f), (o), (l)) ^ \
	 __FUNC_HASH8((f), (o) + __FTMN_MAX_FUNC_LEN / 4, (l)))

#define __FUNC_HASH2(f, l) \
	(__FUNC_HASH4(f, 0, l) ^ \
	 __FUNC_HASH4(f, __FTMN_MAX_FUNC_LEN / 2, l))

#ifdef __ILP32__
#define __FUNC_HASH(f, l) \
	(unsigned long)(__FUNC_HASH2((f), (l)) ^ (__FUNC_HASH2((f), (l)) >> 32))
#else
#define __FUNC_HASH(f, l)	(unsigned long)__FUNC_HASH2((f), (l))
#endif

#define FTMN_FUNC_HASH(name)	__FUNC_HASH(name, sizeof(name))

#ifdef CFG_CORE_FAULT_MITIGATION
#define FTMN_CALL_FUNC(res, ftmn_check, incr, func, ...) \
	do { \
		struct ftmn_func_arg __ftmn_arg = { }; \
		\
		__ftmn_arg.hash = FTMN_FUNC_HASH(__func__); \
		(res) = func(__VA_ARGS__, &__ftmn_arg); \
		ftmn_check_call_done(&__ftmn_arg, \
				     FTMN_FUNC_HASH(__func__) ^ \
				     FTMN_FUNC_HASH(#func), \
				     (res), (ftmn_check), incr); \
	} while (0)

#define FTMN_CALL_VOID_FUNC(ftmn_check, incr, func, ...) \
	do { \
		struct ftmn_func_arg __ftmn_arg = { }; \
		\
		__ftmn_arg.hash = FTMN_FUNC_HASH(__func__); \
		func(__VA_ARGS__, &__ftmn_arg); \
		ftmn_check_call_done(&__ftmn_arg, \
				     FTMN_FUNC_HASH(__func__) ^ \
				     FTMN_FUNC_HASH(#func), \
				     0, (ftmn_check), incr); \
	} while (0)
#else
#define FTMN_CALL_FUNC(res, ftmn_check, incr, func, ...) \
	do { (res) = func(__VA_ARGS__, NULL); } while (0)
#define FTMN_CALL_VOID_FUNC(ftmn_check, incr, func, ...) \
	do { func(__VA_ARGS__, NULL); } while (0)
#endif
#define FTMN_CALLEE_DONE(arg, res) \
	ftmn_callee_done((arg), FTMN_FUNC_HASH(__func__), (res))


#define FTMN_STEP_COUNT1(c0)			((c0) * FTMN_INCR0)
#define FTMN_STEP_COUNT2(c0, c1)		(FTMN_STEP_COUNT1(c0) + \
						 (c1) * FTMN_INCR1)
#define FTMN_STEP_COUNT3(c0, c1, c2)		(FTMN_STEP_COUNT2(c0, c1) + \
						 (c2) * FTMN_INCR2)
#define FTMN_STEP_COUNT4(c0, c1, c2, c3)	\
			(FTMN_STEP_COUNT3(c0, c1, c2) + (c3) * FTMN_INCR3)
#define FTMN_STEP_COUNT5(c0, c1, c2, c3, c4)	\
			(FTMN_STEP_COUNT4(c0, c1, c2, c3) + (c4) * FTMN_INCR4)
#define FTMN_STEP_COUNT6(c0, c1, c2, c3, c4, c5)	\
			(FTMN_STEP_COUNT5(c0, c1, c2, c3, c4) + \
			 (c5) * FTMN_INCR5)

static inline void ftmn_panic(void)
{
#ifdef __KERNEL__
	panic();
#else
	TEE_Panic(0);
#endif
}

void __ftmn_change_val(struct ftmn_check *check, enum ftmn_incr incr,
		       unsigned long hash, unsigned long old_val,
		       unsigned long new_val);
void __ftmn_rehash_val(struct ftmn_check *check, enum ftmn_incr incr,
		       unsigned long old_hashed_val, unsigned long old_hash,
		       unsigned long new_hash, unsigned long val);
unsigned long __ftmn_return_val(unsigned long hashed_val, unsigned long hash,
				unsigned long val);
void __ftmn_expect_val(struct ftmn_check *check, enum ftmn_incr incr,
		       unsigned long ret, unsigned long val);
void __ftmn_expect_not_val(struct ftmn_check *check, enum ftmn_incr incr,
			   unsigned long ret, unsigned long val);


static inline void ftmn_callee_done(struct ftmn_func_arg *arg,
				    unsigned long hash, unsigned long ret)
{
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION)) {
		barrier();
		arg->hash ^= hash;
		arg->ret = arg->hash ^ ret;
		barrier();
	}
}

static inline void ftmn_checkpoint(struct ftmn_check *check,
				   enum ftmn_incr incr)
{
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION)) {
		barrier();
		check->steps += incr;
		barrier();
	}
}

static inline void ftmn_check_call_done(struct ftmn_func_arg *arg,
					unsigned long hash, unsigned long ret,
					struct ftmn_check *check,
					enum ftmn_incr incr)
{
	/*
	 * Transfer the return value into check with a new xor mask. This
	 * verifies the saved value with the old hash so this is also a
	 * check that the hash is correct, that is, that the function
	 * really was called.
	 */
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION))
		__ftmn_rehash_val(check, incr, arg->ret, hash,
				  FTMN_DEFAULT_HASH, ret);
}

static inline void ftmn_expect_val(struct ftmn_check *check,
				   enum ftmn_incr incr, unsigned long ret,
				   unsigned long val)
{
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION))
		__ftmn_expect_val(check, incr, ret, val);
}

static inline void ftmn_expect_not_val(struct ftmn_check *check,
				       enum ftmn_incr incr, unsigned long ret,
				       unsigned long val)
{
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION))
		__ftmn_expect_not_val(check, incr, ret, val);
}

static inline void ftmn_save_val(struct ftmn_check *check, enum ftmn_incr incr,
				 unsigned long val)
{
	ftmn_expect_val(check, incr, val, val);
}

static inline void ftmn_save_ptr(struct ftmn_check *check, enum ftmn_incr incr,
				 void *p)
{
	ftmn_save_val(check, incr, (unsigned long)p);
}

static inline void ftmn_expect_nonzero(struct ftmn_check *check,
				       enum ftmn_incr incr, unsigned long ret)
{
	ftmn_expect_not_val(check, incr, ret, 0);
}

static inline void ftmn_expect_null(struct ftmn_check *check,
				    enum ftmn_incr incr, void *p)
{
	ftmn_expect_val(check, incr, (unsigned long)p, 0);
}

static inline void ftmn_expect_not_null(struct ftmn_check *check,
					enum ftmn_incr incr, void *p)
{
	ftmn_expect_nonzero(check, incr, (unsigned long)p);
}

static inline void ftmn_expect_state(struct ftmn_check *check,
				     unsigned long steps, unsigned long val)
{
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION)) {
		ftmn_expect_val(check, FTMN_INCR_RESERVED, check->steps, steps);
		if ((check->val ^ FTMN_DEFAULT_HASH) != val)
			ftmn_panic();
		if (check->steps != (steps + FTMN_INCR_RESERVED))
			ftmn_panic();
	}
}

static inline unsigned long ftmn_return_val(struct ftmn_check *check,
					    unsigned long val)
{
	if (IS_ENABLED(CFG_CORE_FAULT_MITIGATION))
		return __ftmn_return_val(check->val, FTMN_DEFAULT_HASH, val);
	return val;
}

#endif /*__FAULT_MITIGATION_H*/
