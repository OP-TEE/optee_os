// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"

/*************************************************************
 *
 *   HELPER FUNCTIONS
 *
 *************************************************************/

/*------------------------------------------------------------
 *
 *  __mpa_divby2
 *
 */
static void __mpa_divby2(mpanum op)
{
	mpa_word_t i;
	/* The bit of the word which will be shifted into another word. */
	mpa_word_t rbit;
	int msw_became_zero;

	if (__mpanum_is_zero(op))
		return;

	msw_became_zero = ((__mpanum_msw(op) >> 1) == 0) ? 1 : 0;

	op->d[0] = op->d[0] >> 1;
	for (i = 1; i < __mpanum_size(op); i++) {
		rbit = op->d[i] & 0x01;
		op->d[i] = op->d[i] >> 1;
		op->d[i - 1] ^= (rbit << (WORD_SIZE - 1));
	}
	/* update the size of dest */
	if (__mpanum_sign(op) == MPA_NEG_SIGN)
		op->size += msw_became_zero;
	else
		op->size -= msw_became_zero;
}

/*------------------------------------------------------------
 *
 *  __mpa_mulby2
 *
 */
/*
static void __mpa_mulby2(mpanum op)
{
	mpa_word_t i;
	mpa_word_t rbit;
	mpa_word_t need_extra_word;

	if (__mpanum_is_zero(op))
		return;

	need_extra_word = (__mpanum_msw(op) & (1 << (WORD_SIZE - 1)))?1:0;

	if (need_extra_word)
		i = __mpanum_size(op);
	else
		i = __mpanum_size(op) - 1;
	while (i > 0) {
		rbit = op->d[i-1] >> (WORD_SIZE - 1);
		op->d[i] = op->d[i] << 1;
		op->d[i] ^= rbit;
		i--;
	}
	rbit = op->d[0] >> (WORD_SIZE - 1);

	if (__mpanum_sign(op) == MPA_POS_SIGN)
		op->size += need_extra_word;
	else
		op->size -= need_extra_word;
}
*/

/*  --------------------------------------------------------------------
 *  Function:  __mpa_egcd
 *
 *  Given non-negative integers x and y where y < x, we compute
 *  gcd, a and b such that
 *  a*x + b*y = gcd
 *
 *  gcd must be distrinct and non-zero, that is,
 *  it cannot point to the same mpanum as x_in or y_in or be a null pointer.
 */
static void __mpa_egcd(mpanum gcd,
		       mpanum a,
		       mpanum b,
		       const mpanum x_in,
		       const mpanum y_in, mpa_scratch_mem pool)
{
	mpanum A;
	mpanum B;
	mpanum C;
	mpanum D;
	mpanum x;
	mpanum y;
	mpanum u;
	mpa_word_t k;

	/* have y < x from assumption */
	if (__mpanum_is_zero(y_in)) {
		if (a != 0)
			mpa_set_word(a, 1);
		if (b != 0)
			mpa_set_word(b, 0);
		mpa_copy(gcd, x_in);
		return;
	}
	mpa_alloc_static_temp_var(&x, pool);
	mpa_copy(x, x_in);
	mpa_alloc_static_temp_var(&y, pool);
	mpa_copy(y, y_in);

	k = 0;
	while (mpa_is_even(x) && mpa_is_even(y)) {
		k++;
		__mpa_divby2(x);
		__mpa_divby2(y);
	}

	mpa_alloc_static_temp_var(&u, pool);
	mpa_copy(u, x);
	mpa_copy(gcd, y);
	mpa_alloc_static_temp_var(&A, pool);
	mpa_set_word(A, 1);
	mpa_alloc_static_temp_var(&B, pool);
	mpa_set_word(B, 0);
	mpa_alloc_static_temp_var(&C, pool);
	mpa_set_word(C, 0);
	mpa_alloc_static_temp_var(&D, pool);
	mpa_set_word(D, 1);

	while (!__mpanum_is_zero(u)) {
		while (mpa_is_even(u)) {
			__mpa_divby2(u);
			if (mpa_is_odd(A) || mpa_is_odd(B)) {
				mpa_add(A, A, y, pool);
				mpa_sub(B, B, x, pool);
			}
			__mpa_divby2(A);
			__mpa_divby2(B);
		}

		while (mpa_is_even(gcd)) {
			__mpa_divby2(gcd);
			if (mpa_is_odd(C) || mpa_is_odd(D)) {
				mpa_add(C, C, y, pool);
				mpa_sub(D, D, x, pool);
			}
			__mpa_divby2(C);
			__mpa_divby2(D);
		}

		if (mpa_cmp(u, gcd) >= 0) {
			mpa_sub(u, u, gcd, pool);
			mpa_sub(A, A, C, pool);
			mpa_sub(B, B, D, pool);
		} else {
			mpa_sub(gcd, gcd, u, pool);
			mpa_sub(C, C, A, pool);
			mpa_sub(D, D, B, pool);
		}
	}

	/* copy results */
	if (a != 0)
		mpa_copy(a, C);
	if (b != 0)
		mpa_copy(b, D);
	mpa_shift_left(gcd, gcd, k);

	mpa_free_static_temp_var(&A, pool);
	mpa_free_static_temp_var(&B, pool);
	mpa_free_static_temp_var(&C, pool);
	mpa_free_static_temp_var(&D, pool);
	mpa_free_static_temp_var(&x, pool);
	mpa_free_static_temp_var(&y, pool);
	mpa_free_static_temp_var(&u, pool);
}

/*  --------------------------------------------------------------------
 *  Function:  __mpa_gcd
 *  Computes the gcd of x and y where y <= x.
 *  Destination variable gcd must be allocated.
 */
static void __mpa_gcd(mpanum gcd,
		      const mpanum x_in,
		      const mpanum y_in, mpa_scratch_mem pool)
{
	mpanum x;
	mpanum y;
	mpanum t;
	mpa_word_t k;

	/* have y < x from assumption */
	if (__mpanum_is_zero(y_in)) {
		mpa_copy(gcd, x_in);
		return;
	}
	mpa_alloc_static_temp_var(&x, pool);
	mpa_copy(x, x_in);
	mpa_alloc_static_temp_var(&y, pool);
	mpa_copy(y, y_in);

	k = 0;
	while (mpa_is_even(x) && mpa_is_even(y)) {
		k++;
		__mpa_divby2(x);
		__mpa_divby2(y);
	}

	mpa_alloc_static_temp_var(&t, pool);
	while (!__mpanum_is_zero(x)) {
		while (mpa_is_even(x))
			__mpa_divby2(x);

		while (mpa_is_even(y))
			__mpa_divby2(y);

		mpa_sub(t, x, y, pool);
		/* abs val of t */
		__mpanum_set_sign(t, MPA_POS_SIGN);
		__mpa_divby2(t);
		if (mpa_cmp(x, y) >= 0)
			mpa_copy(x, t);
		else
			mpa_copy(y, t);
	}

	mpa_shift_left(gcd, y, k);
	mpa_free_static_temp_var(&t, pool);
	mpa_free_static_temp_var(&x, pool);
	mpa_free_static_temp_var(&y, pool);
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:  mpa_gcd
 *
 *  Computes the GCD of src1 and src2
 */
void mpa_gcd(mpanum dest,
	     const mpanum src1, const mpanum src2, mpa_scratch_mem pool)
{
	int cmp;
	int sign1;
	int sign2;

	/* remember sign and take abs value */
	sign1 = __mpanum_sign(src1);
	sign2 = __mpanum_sign(src2);
	__mpanum_set_sign(src1, MPA_POS_SIGN);
	__mpanum_set_sign(src2, MPA_POS_SIGN);

	cmp = mpa_cmp(src1, src2);
	if (cmp == 0) {
		mpa_copy(dest, src1);
		goto cleanup;
	}
	if (cmp < 0) {		/* src1 < src2, swap data */
		__mpa_gcd(dest, src2, src1, pool);
	} else {
		__mpa_gcd(dest, src1, src2, pool);
	}

cleanup:
	/* restore sign */
	__mpanum_set_sign(src1, sign1);
	__mpanum_set_sign(src2, sign2);
}

/*  --------------------------------------------------------------------
 *  Function:  mpa_extended_gcd
 *
 *  Computes gcd, dest1 and dest2 such that
 *  dest1*src1 + dest2*src2 = gcd
 *
 *  May be called with gcd, dest1 and/or dest2 == 0.
 *
 */
void mpa_extended_gcd(mpanum gcd,
		      mpanum dest1,
		      mpanum dest2,
		      const mpanum src1,
		      const mpanum src2, mpa_scratch_mem pool)
{
	int cmp;
	int sign1;
	int sign2;
	int mem_marker;
	mpanum tmp_gcd;

	if (dest1 == 0 && dest2 == 0) {
		if (gcd != 0)
			mpa_gcd(gcd, src1, src2, pool);
		return;
	}

	/* remember sign and take abs value */
	sign1 = __mpanum_sign(src1);
	sign2 = __mpanum_sign(src2);
	__mpanum_set_sign(src1, MPA_POS_SIGN);
	__mpanum_set_sign(src2, MPA_POS_SIGN);

	cmp = mpa_cmp(src1, src2);
	if (cmp == 0) {
		if (gcd != 0)
			mpa_copy(gcd, src1);
		if (dest1 != 0)
			mpa_set_word(dest1, 1);
		if (dest2 != 0)
			mpa_set_word(dest2, 0);
		goto cleanup;
	}

	mem_marker = (gcd == 0 || gcd == src1 || gcd == src2);
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_gcd, pool);
	else
		tmp_gcd = gcd;

	if (cmp < 0)		/* src1 < src2, swap data */
		__mpa_egcd(tmp_gcd, dest2, dest1, src2, src1, pool);
	else
		__mpa_egcd(tmp_gcd, dest1, dest2, src1, src2, pool);

	if (gcd != 0)
		mpa_copy(gcd, tmp_gcd);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_gcd, pool);

cleanup:
	/* restore sign */
	__mpanum_set_sign(src1, sign1);
	__mpanum_set_sign(src2, sign2);
	/* change resulting signs if needed */
	if (sign1 == MPA_NEG_SIGN && dest1 != 0)
		__mpanum_neg(dest1);
	if (sign2 == MPA_NEG_SIGN && dest2 != 0)
		__mpanum_neg(dest2);
}
