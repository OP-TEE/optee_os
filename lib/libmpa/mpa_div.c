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
 *  These functions have ARM assembler implementations
 *
 */
#if !defined(USE_ARM_ASM)

static mpa_dword_t __mpa_soft_div(mpa_dword_t num, mpa_word_t den_in,
				  mpa_word_t *rem)
{
	mpa_dword_t quot = 0, qbit = 1;
	mpa_dword_t den = den_in;

	while ((int64_t) den >= 0) {
		den <<= 1;
		qbit <<= 1;
	}

	while (qbit) {
		if (den <= num) {
			num -= den;
			quot += qbit;
		}
		den >>= 1;
		qbit >>= 1;
	}

	if (rem)
		*rem = (mpa_word_t) num;

	return quot;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_div_dword
 *
 *  Calculates quotient and remainder of (n1*base + n0) / d.
 *  It is assumed that the quotient is small enough to fit a single word.
 */
mpa_word_t __mpa_div_dword(mpa_word_t n0,
			   mpa_word_t n1, mpa_word_t d, mpa_word_t *r)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t n;
	/*    mpa_dword_t tmp_q; */

	n = ((mpa_dword_t) n1 << WORD_SIZE) + n0;
	return __mpa_soft_div(n, d, r);
	/*    tmp_q = n / d; */
	/*    *r = (mpa_word_t)(n % d); */
	/*    return tmp_q; */
#else
#error write non-dword code for __mpa_div_dword
#endif
}

#endif /* USE_ARM_ASM */

/*  --------------------------------------------------------------------
 *  Function:   __mpa_div_q_r_internal
 *
 *  Finds the quotient and remainder when |op1| is divided by |op2|.
 *  q, r, op1 and op2 must all be distinct and not null.
 *  E.i. we get q and r such that |op1| = q*|op2| + r, 0<= r < |op2|.
 *  Assumptions: |op1| >= |op2| and |op2| >= 2^(WORD_SIZE)
 *
 */
static void __mpa_div_q_r_internal(mpanum q,
				   mpanum r,
				   const mpanum op1,
				   const mpanum op2, mpa_scratch_mem pool)
{
	mpa_word_t normshift;
	int base_diff;
	int i;
	int cmp_same;
	mpa_usize_t n;		/* size of op1 */
	mpa_usize_t t;		/* size of op2 */
	mpa_word_t w1;
	mpa_word_t w2;
	mpa_word_t w3;
	mpa_word_t w4;
	mpa_word_t w5;
	mpanum p;
	mpanum y;
	mpanum x;

	/*
	 *  get temp storage
	 */
	mpa_alloc_static_temp_var(&p, pool);
	mpa_alloc_static_temp_var(&y, pool);
	mpa_copy(y, op2);

	/*
	 * May need a large value for r since op1 may be an "oversized"
	 * value that is reduced. x is used for that internally and it's
	 * initial value is op1.
	 */
	mpa_alloc_static_temp_var(&x, pool);
	mpa_copy(x, op1);
	__mpanum_set_sign(x, MPA_POS_SIGN);
	__mpanum_set_sign(y, MPA_POS_SIGN);

	/*
	 *  Normalization
	 */
	normshift = 0;
	w1 = __mpanum_msw(y);
	while (w1 < ((mpa_word_t)1 << (WORD_SIZE - 1))) {
		normshift++;
		w1 <<= 1;
	}
	if (normshift) {
		mpa_shift_left(x, x, normshift);
		mpa_shift_left(y, y, normshift);
	}

	n = x->size;
	t = y->size;
	base_diff = (int)n - t;

	mpa_wipe(q);

	/*
	 * check if op1 >= op2*base^(base_diff)
	 */
	/* mpa_shift_left(y, y, base_diff * WORD_SIZE); */
	__mpa_shift_words_left(y, base_diff);

	i = __mpanum_size(y);
	cmp_same = 1;
	while (cmp_same != 0 && i > 0) {
		i--;
		cmp_same = (__mpanum_get_word(i, x) == __mpanum_get_word(i, y));
	}
	if (!cmp_same && (__mpanum_get_word(i, x) > __mpanum_get_word(i, y))) {
		q->d[base_diff] = 1;
		mpa_sub(x, x, y, pool);
	}

	/* start main division loop */
	i = x->size - 1;
	while (i >= (int)t) {
		if (__mpanum_get_word(i, x) ==
		    __mpanum_get_word(t + base_diff - 1, y)) {
			q->d[i - t] = WORD_ALL_BITS_ONE;
		} else {
			q->d[i - t] =
				__mpa_div_dword(__mpanum_get_word(i - 1, x),
						__mpanum_get_word(i, x),
						__mpanum_get_word(t + base_diff
								  - 1, y),
						NULL);
		}
		while (1) {
			/* set incoming carry to zero for all three ops */
			w1 = 0;
			w3 = 0;
			w5 = 0;
			__mpa_mul_add_word(q->d[i - t],
					   __mpanum_get_word(t + base_diff - 1,
							   y), &w2, &w1);

			if (w1 > __mpanum_get_word(i, x))
				goto loop_dec;

			__mpa_mul_add_word(q->d[i - t],
					   __mpanum_get_word(t + base_diff - 2,
							   y), &w4, &w3);

			__mpa_full_adder(w2, w3, &w3, &w5);
			w2 = 0;	/* used as carry */
			__mpa_full_adder(w1, w5, &w5, &w2);
			if (w2 || w5 > __mpanum_get_word(i, x))
				goto loop_dec;
			if (w5 < __mpanum_get_word(i, x))
				break;
			if (w3 > __mpanum_get_word(i - 1, x))
				goto loop_dec;
			if (w3 < __mpanum_get_word(i - 1, x))
				break;
			if (w4 > __mpanum_get_word(i - 2, x))
				goto loop_dec;
			break;
loop_dec:
			q->d[i - t]--;
		}

		/* mpa_shift_right(y, y, WORD_SIZE); */
		__mpa_shift_words_right(y, 1);
		base_diff--;
		mpa_mul_word(p, y, q->d[i - t], pool);
		mpa_sub(x, x, p, pool);
		if (__mpanum_sign(x) == MPA_NEG_SIGN) {
			mpa_add(x, x, y, pool);
			q->d[i - t]--;
		}
		i--;
	}
	/*
	 *  Find size of q
	 */
	i = n - t;
	while (i >= 0 && q->d[i] == 0)
		i--;
	q->size = i + 1;
	/*
	 *  Divide r by the normalization value and copy to output
	 */
	mpa_shift_right(x, x, normshift);
	mpa_copy(r, x);

	/*
	 *  release p, y, and x
	 */
	mpa_free_static_temp_var(&p, pool);
	mpa_free_static_temp_var(&y, pool);
	mpa_free_static_temp_var(&x, pool);
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_div_q_r_internal_word
 *
 *  Finds the quotient and remainder when |op1| is divided by |op2|, where
 *  op2 is a word.
 *  q, r and op1 must all be distinct and not null.
 *  E.i. we get q and r such that |op1| = q*|op2| + r, 0<= r < |op2|.
 *  Assumptions: |op1| >= |op2|.

 */
void __mpa_div_q_r_internal_word(mpanum q,
				 mpanum r,
				 const mpanum op1, const mpa_word_t op2)
{
	int pos1;
	mpa_word_t q_word;
	mpa_word_t r_word;
	mpa_word_t n1;
	mpa_word_t n0;
	int i;

	if (__mpanum_size(op1) == 1) {
		mpa_set_word(q, op1->d[0] / op2);
		mpa_set_word(r, op1->d[0] % op2);
		return;
	}
	mpa_copy(r, op1);
	mpa_set_word(q, 0);

	pos1 = (int)__mpanum_size(r) - 1;
	n1 = 0;
	n0 = r->d[pos1];
	while (pos1 >= 0) {
		q_word = __mpa_div_dword(n0, n1, op2, &r_word);
		q->d[pos1] = q_word;
		r->d[pos1] = r_word;
		n1 = r->d[pos1];
		n0 = r->d[--pos1];
	}
	/* set sizes of r and q */
	r->size = (r->d[0] == 0 ? 0 : 1);
	i = __mpanum_size(op1) - 1;
	while (i >= 0 && q->d[i] == 0)
		i--;
	q->size = i + 1;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_div_q_r
 *
 *  Calculates the quotient and remainder when op1 is divided by op2.
 *  q, r, op1 and op2 must all be distinct and not null, except that op1
 *  may be equal to op2.
 *  There must be enough space allocated in q and r to handle the results.
 *  If op2 is zero a division with zero will be executed and the above layers
 *  can handle that as it pleases.
 *  The sign of q and r are shown in the table:
 *  __________________________________
 *  | Sign(q/r) | op1 >= 0 | op1 < 0 |
 *  |--------------------------------|
 *  | op2 > 0   |    +/+   |  -/-    |
 *  |--------------------------------|
 *  | op2 < 0   |    -/+   |  +/-    |
 *  |________________________________|
 */
void __mpa_div_q_r(mpanum q,
		   mpanum r,
		   const mpanum op1, const mpanum op2, mpa_scratch_mem pool)
{
	int q_sign;
	int cmp;

	if (__mpanum_is_zero(op1)) {
		mpa_set_word(q, 0);
		mpa_set_word(r, 0);
		return;
	}
	if (__mpanum_is_zero(op2)) {
		/* generate a divide by zero error */
		q_sign = 42 / op2->size;
		return;
	}

	q_sign =
	    (__mpanum_sign(op1) !=
	     __mpanum_sign(op2)) ? MPA_NEG_SIGN : MPA_POS_SIGN;
	cmp = __mpa_abs_cmp(op1, op2);
	if (cmp == 0) {
		mpa_set_word(q, 1);
		mpa_set_word(r, 0);
		return;
	}
	if (cmp > 0) {		/* |op1| > |op2| */
		if (__mpanum_size(op2) > 1)
			__mpa_div_q_r_internal(q, r, op1, op2, pool);
		else
			__mpa_div_q_r_internal_word(q, r, op1, op2->d[0]);
	} else {		/* |op1| < |op2| */
		mpa_set_word(q, 0);
		mpa_copy(r, op1);
		return;
	}
	__mpanum_set_sign(q, q_sign);
	__mpanum_set_sign(r, __mpanum_sign(op1));
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   mpa_div
 *
 *  Returns the quotient and the remainder of op1 divided by op2.
 *   q and r must be distinct variables.
 *  This function returns q and r such that
 *  op1 = q*op2 + r
 *  where 0 <= r < |op2|
 */
void mpa_div(mpanum q,
	     mpanum r, const mpanum op1, const mpanum op2, mpa_scratch_mem pool)
{
	mpanum tmp_q;
	mpanum tmp_r;
	char mem_marker_q;
	char mem_marker_r;

	/* handle the case when q is one of the operands or zero */
	if (q == op1 || q == op2 || q == 0) {
		mpa_alloc_static_temp_var(&tmp_q, pool);
		mem_marker_q = 1;
	} else {
		tmp_q = q;
		mem_marker_q = 0;
	}

	/* handle the case when r is one of the operands or zero */
	if (r == op1 || r == op2 || r == 0) {
		mpa_alloc_static_temp_var(&tmp_r, pool);
		mem_marker_r = 1;
	} else {
		tmp_r = r;
		mem_marker_r = 0;
	}

	__mpa_div_q_r(tmp_q, tmp_r, op1, op2, pool);

	if (q != 0)
		mpa_copy(q, tmp_q);
	if (mem_marker_q)
		mpa_free_static_temp_var(&tmp_q, pool);
	if (r != 0)
		mpa_copy(r, tmp_r);
	if (mem_marker_r)
		mpa_free_static_temp_var(&tmp_r, pool);
}
