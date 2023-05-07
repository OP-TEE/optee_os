// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <compiler.h>
#include <fault_mitigation.h>

#ifndef __KERNEL__
struct ftmn_func_arg *__ftmn_global_func_arg;
#endif

/*
 * These functions can be implemented in assembly if needed. They would
 * provide the same API but an implementation more resilient to fault
 * injections.
 *
 * For now there is no need since it's enough with the single redundancy
 * provided just by having these function implemented separately from where
 * they are used.
 */

unsigned long __weak ___ftmn_return_res(struct ftmn_check *check,
					unsigned long steps, unsigned long res)
{
	if (check->steps != steps)
		FTMN_PANIC();
	if ((check->res ^ FTMN_DEFAULT_HASH) != res)
		FTMN_PANIC();
	return res;
}

void __weak ___ftmn_expect_state(struct ftmn_check *check, enum ftmn_incr incr,
				 unsigned long steps, unsigned long res)
{
	if ((check->res ^ FTMN_DEFAULT_HASH) != res)
		FTMN_PANIC();
	if (check->steps != steps)
		FTMN_PANIC();
	check->steps += incr;
}

void __weak ___ftmn_callee_done(struct ftmn_func_arg *arg,
				unsigned long my_hash,
				unsigned long res)
{
	arg->hash ^= my_hash;
	arg->res = arg->hash ^ res;
}

void __weak ___ftmn_callee_done_not_zero(struct ftmn_func_arg *arg,
					 unsigned long my_hash,
					 unsigned long res)
{
	if (res == 0)
		FTMN_PANIC();
	arg->hash ^= my_hash;
	arg->res = arg->hash ^ res;
}

void __weak ___ftmn_callee_done_memcmp(struct ftmn_func_arg *arg,
				       unsigned long my_hash, int res,
				       ftmn_memcmp_t my_memcmp,
					const void *p1, const void *p2,
					size_t nb)
{
	int res2 = 0;

	if (!nb)
		FTMN_PANIC();

	res2 = my_memcmp(p1, p2, nb);
	if (res2 != res)
		FTMN_PANIC();

	arg->hash ^= my_hash;
	arg->res = arg->hash ^ res;
}

void __weak ___ftmn_callee_done_check(struct ftmn_func_arg *arg,
				      unsigned long my_hash,
				      struct ftmn_check *check,
				      enum ftmn_incr incr, unsigned long steps,
				      unsigned long res)
{
	if ((check->res ^ FTMN_DEFAULT_HASH) != res)
		FTMN_PANIC();
	if (check->steps != steps)
		FTMN_PANIC();

	check->steps += incr;
	if (arg) {
		arg->hash ^= my_hash;
		arg->res = check->res ^ FTMN_DEFAULT_HASH ^ arg->hash;
	}

}

void ___ftmn_callee_update_not_zero(struct ftmn_func_arg *arg,
				    unsigned long res)
{
	if (!res)
		FTMN_PANIC();
	arg->res = arg->hash ^ res;
}


void __weak ___ftmn_copy_linked_call_res(struct ftmn_check *check,
					 enum ftmn_incr incr,
					 struct ftmn_func_arg *arg,
					 unsigned long res)
{
	if ((arg->res ^ arg->hash) != res)
		FTMN_PANIC();
	check->res = res ^ FTMN_DEFAULT_HASH;
	check->steps += incr;
}

void __weak ___ftmn_set_check_res(struct ftmn_check *check, enum ftmn_incr incr,
				  unsigned long res)
{
	check->steps += incr;
	check->res = res ^ FTMN_DEFAULT_HASH;
}

void __weak ___ftmn_set_check_res_not_zero(struct ftmn_check *check,
					   enum ftmn_incr incr,
					   unsigned long res)
{
	if (!res)
		FTMN_PANIC();
	check->steps += incr;
	check->res = res ^ FTMN_DEFAULT_HASH;
}

void __weak ___ftmn_set_check_res_memcmp(struct ftmn_check *check,
					 enum ftmn_incr incr, int res,
					 ftmn_memcmp_t my_memcmp,
					 const void *p1, const void *p2,
					 size_t nb)
{
	int res2 = 0;

	if (!nb)
		FTMN_PANIC();

	res2 = my_memcmp(p1, p2, nb);
	if (res2 != res)
		FTMN_PANIC();

	check->steps += incr;
	check->res = FTMN_DEFAULT_HASH ^ res;
}
