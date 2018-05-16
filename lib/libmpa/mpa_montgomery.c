// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"

/*************************************************************
 *
 *   HELPERS
 *
 *************************************************************/

/*------------------------------------------------------------
 *
 *  These functions have ARM assembler implementations
 *
 */
#if !defined(USE_ARM_ASM)

/*  --------------------------------------------------------------------
 *  Function:  __mpa_montgomery_mul_add
 *  Calculates dest = dest + src*w
 *  Dest must be big enough to hold the result
 */
void __mpa_montgomery_mul_add(mpanum dest, mpanum src, mpa_word_t w)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t a;
	mpa_word_t *ddig;
	int32_t idx;
	mpa_word_t carry;
	mpa_word_t *dest_begin;

	if (w == 0)
		return;
	dest_begin = dest->d;
	ddig = dest->d;
	carry = 0;
	for (idx = 0; idx < src->size; idx++) {
		a = (mpa_dword_t) *ddig +
		    (mpa_dword_t) src->d[idx] * (mpa_dword_t) w +
		    (mpa_dword_t) (carry);
		*(ddig++) = (mpa_word_t) (a);
		carry = (mpa_word_t) (a >> WORD_SIZE);
	}
	while (carry) {
		a = (mpa_dword_t) (*ddig) + (mpa_dword_t) (carry);
		*(ddig++) = (mpa_word_t) (a);
		carry = (mpa_word_t) (a >> WORD_SIZE);
	}
	idx = (mpa_word_t) (ddig - dest_begin);
	if (idx > dest->size)
		dest->size = idx;

#else
#error write non-dword code for __mpa_montgomery_mul_add
#endif
}

/*  --------------------------------------------------------------------
 *  Function:  __mpa_montgomery_sub_ack
 *  Calculates dest = dest - src
 *  Assumption: dest >= src and both non-negative
 *  and dest > src.
 *
 */
void __mpa_montgomery_sub_ack(mpanum dest, mpanum src)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_word_t *ddig;
	mpa_word_t carry;
	int32_t idx;
	mpa_dword_t a;

	ddig = dest->d;
	carry = 0;
	idx = 0;
	while (idx < src->size) {
		a = (mpa_dword_t) (*ddig) - (mpa_dword_t) src->d[idx] -
		    (mpa_dword_t) carry;
		*(ddig++) = (mpa_word_t) (a);
		carry = 0 - (mpa_word_t) (a >> WORD_SIZE);
		idx++;
	}
	/* Here we have no more digits in op2, we only need to keep on
	 * subtracting 0 from op1, and deal with carry */
	while (carry) {
		a = (mpa_dword_t) (*ddig) - (mpa_dword_t) carry;
		*(ddig++) = (mpa_word_t) (a);
		carry = 0 - (mpa_word_t) (a >> WORD_SIZE);
		idx++;
	}
	if (idx >= dest->size) {
		/* carry did propagate all the way, fix size */
		while (dest->size > 0 && *(--ddig) == 0)
			dest->size--;
	}
#else
#error write non-dword code for __mpa_montgomery_sub_ack
#endif
}

#endif /* USE_ARM_ASM */

/*------------------------------------------------------------
 *
 *  __mpa_montgomery_mul
 *
 *  NOTE:
 *  Dest need to be able to hold one more word than the size of n
 *
 */
void __mpa_montgomery_mul(mpanum dest, mpanum op1, mpanum op2, mpanum n,
			  mpa_word_t n_inv)
{
	mpa_word_t u;
	mpa_usize_t idx;

	/* set dest to zero (with all unused digits to zero as well) */
	mpa_wipe(dest);

	for (idx = 0; idx < n->size; idx++) {
		u = (dest->d[0] +
		     __mpanum_get_word(idx, op1) *
		     __mpanum_get_word(0, op2)) * n_inv;

		__mpa_montgomery_mul_add(dest, op2,
					 __mpanum_get_word(idx, op1));
		__mpa_montgomery_mul_add(dest, n, u);

		/* Shift right one mpa_word */
		dest->size--;
		for (mpa_usize_t i = 0; i < dest->size; i++)
			dest->d[i] = dest->d[i + 1];
		*(dest->d + dest->size) = 0;	/* set unused digit to zero. */
	}

	/* check if dest > n, if so set dest = dest - n */
	if (__mpa_abs_cmp(dest, n) >= 0)
		__mpa_montgomery_sub_ack(dest, n);
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*
 * mpa_compute_fmm_context
 */
int mpa_compute_fmm_context(const mpanum modulus,
			    mpanum r_modn,
			    mpanum r2_modn,
			    mpa_word_t *n_inv,
			    mpa_scratch_mem pool)
{
	mpa_usize_t s;
	int cmpresult;
	mpanum tmp_n_inv;
	mpanum gcd;

	/* create a small mpanum on the stack */
	uint32_t n_lsw_u32[MPA_NUMBASE_METADATA_SIZE_IN_U32 + ASIZE_TO_U32(1)];
	mpanum n_lsw = (void *)n_lsw_u32;

	/*
	 * compute r to be
	 * 1 << (__mpanum_size(Modulus) * WORD_SIZE) mod modulus
	 */
	s = __mpanum_size(modulus);
	mpa_set_word(r_modn, 1);
	mpa_shift_left(r_modn, r_modn, s * WORD_SIZE);
	mpa_mod(r_modn, r_modn, modulus, pool);

	/* compute r^2 mod modulus */
	mpa_mul_mod(r2_modn, r_modn, r_modn, modulus, pool);

	/* Compute the inverse of modulus mod 1 << WORD_SIZE */
	n_lsw->alloc = 1;
	n_lsw->size = 1;
	n_lsw->d[0] = __mpanum_lsw(modulus);

	mpa_alloc_static_temp_var(&tmp_n_inv, pool);
	mpa_alloc_static_temp_var(&gcd, pool);

	mpa_extended_gcd(gcd, tmp_n_inv, NULL, n_lsw,
			 (const mpanum)&Const_1_LShift_Base, pool);
	cmpresult = mpa_cmp_short(gcd, 1);

	if (cmpresult != 0)
		goto cleanup;

	/*
	 * We need the number n' (n_inv) such that
	 *
	 * R*r' - N*n' == 1
	 *
	 * and Extended_GCD gives us the solution to
	 *
	 * R*r' + N*n' == 1
	 *
	 * So if n' is negative, we just forget about the sign.
	 * If n' is positive, we need to subtract R to get
	 * the right residue class.
	 */
	if (__mpanum_sign(tmp_n_inv) == MPA_POS_SIGN) {
		mpa_sub(tmp_n_inv, tmp_n_inv,
			(const mpanum)&Const_1_LShift_Base, pool);
	}
	/* then take the absolute value */
	*n_inv = __mpanum_lsw(tmp_n_inv);

cleanup:

	mpa_free_static_temp_var(&gcd, pool);
	mpa_free_static_temp_var(&tmp_n_inv, pool);

	if (cmpresult != 0)
		return -1;
	return 0;
}

/*------------------------------------------------------------
 *
 *  mpa_montgomery_mul
 *
 *  wrapper that uses a temp variables for dest, since
 *  that need to be one word larger that n.
 */
void mpa_montgomery_mul(mpanum dest,
		       mpanum op1,
		       mpanum op2,
		       mpanum n, mpa_word_t n_inv, mpa_scratch_mem pool)
{
	mpanum tmp_dest;

	mpa_alloc_static_temp_var(&tmp_dest, pool);

	__mpa_montgomery_mul(tmp_dest, op1, op2, n, n_inv);

	mpa_copy(dest, tmp_dest);
	mpa_free_static_temp_var(&tmp_dest, pool);
}
