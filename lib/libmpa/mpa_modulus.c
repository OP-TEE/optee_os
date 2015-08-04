/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
