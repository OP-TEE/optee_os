// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*------------------------------------------------------------
 *
 *  mpa_mod
 *
 */
void mpa_mod(mpanum dest, const mpanum op, const mpanum n, mpa_scratch_mem pool)
{
	mpa_div(NULL, dest, op, n, pool);
}

/*------------------------------------------------------------
 *
 *  mpa_add_mod
 *
 */
void mpa_add_mod(mpanum dest,
		const mpanum op1,
		const mpanum op2, const mpanum n, mpa_scratch_mem pool)
{
	mpanum tmp_dest;

	mpa_alloc_static_temp_var(&tmp_dest, pool);

	mpa_add(tmp_dest, op1, op2, pool);
	mpa_div(NULL, dest, tmp_dest, n, pool);

	mpa_free_static_temp_var(&tmp_dest, pool);
}

/*------------------------------------------------------------
 *
 *  mpa_sub_mod
 *
 */
void mpa_sub_mod(mpanum dest,
		const mpanum op1,
		const mpanum op2, const mpanum n, mpa_scratch_mem pool)
{
	mpanum tmp_dest;

	mpa_alloc_static_temp_var(&tmp_dest, pool);

	mpa_sub(tmp_dest, op1, op2, pool);
	mpa_div(NULL, dest, tmp_dest, n, pool);

	mpa_free_static_temp_var(&tmp_dest, pool);
}

/*------------------------------------------------------------
 *
 *  mpa_mul_mod
 *
 */
void mpa_mul_mod(mpanum dest,
		const mpanum op1,
		const mpanum op2, const mpanum n, mpa_scratch_mem pool)
{
	mpanum tmp_dest;

	mpa_alloc_static_temp_var(&tmp_dest, pool);

	mpa_mul(tmp_dest, op1, op2, pool);
	mpa_div(NULL, dest, tmp_dest, n, pool);

	mpa_free_static_temp_var(&tmp_dest, pool);
}

/*------------------------------------------------------------
 *
 *  mpa_inv_mod
 *
 */
int mpa_inv_mod(mpanum dest,
	       const mpanum op, const mpanum n, mpa_scratch_mem pool)
{
	mpanum gcd;
	mpanum tmp_dest;
	int mem_marker;
	int res;

	if (mpa_cmp_short(op, 1) == 0) {
		mpa_set_S32(dest, 1);
		return 0;
	}

	mem_marker = (dest == op);
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	mpa_alloc_static_temp_var(&gcd, pool);
	/* The function mpa_extended_gcd behaves badly if tmp_dest = op */
	mpa_extended_gcd(gcd, tmp_dest, NULL, op, n, pool);
	res = mpa_cmp_short(gcd, 1);

	if (mem_marker) {
		mpa_copy(dest, tmp_dest);
		mpa_free_static_temp_var(&tmp_dest, pool);
	}

	mpa_free_static_temp_var(&gcd, pool);
	if (res == 0) {
		while (mpa_cmp_short(dest, 0) < 0)
			mpa_add(dest, dest, n, pool);
		return 0;
	} else {
		return -1;
	}
}
