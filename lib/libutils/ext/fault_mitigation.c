// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <compiler.h>
#include <fault_mitigation.h>

/*
 * These functions are supposed to be implemented in assembly providing
 * the same API but an implementation more resilient to fault injections.
 *
 * The implementations are here as way of documenting the assembly versions
 * as they are more cryptic than normal assmebly functions.
 */

void __weak __ftmn_change_val(struct ftmn_check *check, enum ftmn_incr incr,
			     unsigned long hash, unsigned long old_val,
			     unsigned long new_val)
{
	if ((check->val ^ hash) != old_val)
		ftmn_panic();
	check->val = new_val ^ hash;
	check->steps += incr;
}

void __weak __ftmn_rehash_val(struct ftmn_check *check, enum ftmn_incr incr,
			      unsigned long old_hashed_val,
			      unsigned long old_hash, unsigned long new_hash,
			      unsigned long val)
{
	if ((old_hashed_val ^ old_hash) != val)
		ftmn_panic();
	check->val = val ^ new_hash;
	check->steps += incr;
}

unsigned long __weak __ftmn_return_val(unsigned long hashed_val,
				       unsigned long hash, unsigned long val)
{
	if ((hashed_val ^ hash) != val)
		ftmn_panic();
	return val;
}

void __weak __ftmn_expect_val(struct ftmn_check *check, enum ftmn_incr incr,
			      unsigned long ret, unsigned long val)
{
	if (ret != val)
		ftmn_panic();
	check->steps += incr;
}

void __weak __ftmn_expect_not_val(struct ftmn_check *check, enum ftmn_incr incr,
				  unsigned long ret, unsigned long val)
{
	if (ret == val)
		ftmn_panic();
	check->steps += incr;
}
