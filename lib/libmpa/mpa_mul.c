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
 *  Function:   __mpa_mul_add_word
 *
 *  Multiplies a and b and adds the incoming carry to produce the product p
 *  outgoing carry is stored in *carry.
 */
void __mpa_mul_add_word(mpa_word_t a,
			mpa_word_t b, mpa_word_t *p, mpa_word_t *carry)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t prod;

	prod = (mpa_dword_t) (a) * (mpa_dword_t) (b) + (mpa_dword_t) (*carry);
	*p = (mpa_word_t) prod;
	*carry = (mpa_word_t) (prod >> MPA_WORD_SIZE);
#else
#error "error, write non-dword_t code for __mpa_mul_add_word"
#endif
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_mul_add_word_cum
 *
 *  Multiplies a and b and adds the incoming carry and the cumulative
 *  product stored in *p.
 *  Outgoing carry is stored in *carry.
 */
void __mpa_mul_add_word_cum(mpa_word_t a,
			    mpa_word_t b, mpa_word_t *p, mpa_word_t *carry)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t prod;

	prod =
	    (mpa_dword_t) (a) * (mpa_dword_t) (b) + (mpa_dword_t) (*p) +
	    (mpa_dword_t) (*carry);
	*p = (mpa_word_t) prod;
	*carry = (mpa_word_t) (prod >> MPA_WORD_SIZE);
#else
#error "error: write non-dword_t code for __mpa_mul_add_word_cum"
#endif
}

#endif /* USE_ARM_ASM */

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_mul_word
 *
 *  Simpler multiplication when one operand is known to be a word.
 *  Calculates |op1| * op2, op2 is always positive (larger than zero).
 *  Dest needs to be distinct from op1.
 */
void __mpa_abs_mul_word(mpanum dest, const mpanum op1, mpa_word_t op2)
{
	mpa_word_t i;
	mpa_word_t carry;
	mpa_word_t *prod;
	const mpa_word_t *a;

	/* clear dest digits */
	mpa_memset(dest->d, 0, dest->alloc * BYTES_PER_WORD);

	a = op1->d;
	prod = dest->d;
	carry = 0;
	for (i = 0; i < __mpanum_size(op1); i++) {
		__mpa_mul_add_word(*a, op2, prod + i, &carry);
		a++;
	}
	dest->size = i;
	if (carry) {
		*(prod + i) = carry;
		dest->size++;
	}
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_mul
 *
 *  Calculates |op1| * |op2| and puts result in dest.
 *  dest must be big enough to hold result and cannot be
 *  the same as op1 or op2.
 */
void __mpa_abs_mul(mpanum dest, const mpanum op1, const mpanum op2)
{
	mpa_word_t i = 0;
	mpa_word_t j = 0;
	mpa_word_t carry = 0;
	mpa_word_t *prod;
	const mpa_word_t *a;
	const mpa_word_t *b;

	/* clear dest digits */
	mpa_memset(dest->d, 0, dest->alloc * BYTES_PER_WORD);

	a = op1->d;
	prod = dest->d;
	for (i = 0; i < __mpanum_size(op1); i++) {
		b = op2->d;
		carry = 0;
		for (j = 0; j < __mpanum_size(op2); j++) {
			__mpa_mul_add_word_cum(*a, *b, prod + j, &carry);
			b++;
		}
		if (carry)
			*(prod + j) = carry;
		a++;
		prod++;
	}
	dest->size = i + j - 1;
	if (carry)
		dest->size++;
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   mpa_mul
 *
 *  dest = op1 * op2
 */
void mpa_mul(mpanum dest,
	     const mpanum op1, const mpanum op2, mpa_scratch_mem pool)
{
	mpanum tmp_dest;
	char mem_marker;

	if (__mpanum_is_zero(op1) || __mpanum_is_zero(op2)) {
		mpa_set_word(dest, 0);
		return;
	}

	/* handle the case when dest is one of the operands */
	mem_marker = (dest == op1 || dest == op2);
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	__mpa_abs_mul(tmp_dest, op1, op2);

	if (__mpanum_sign(op1) != __mpanum_sign(op2))
		__mpanum_neg(tmp_dest);

	mpa_copy(dest, tmp_dest);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_dest, pool);
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_mul_word
 *
 *  Calculates op1 * op2, where op2 is a word, puts result in dest.
 */
void mpa_mul_word(mpanum dest,
		 const mpanum op1, mpa_word_t op2, mpa_scratch_mem pool)
{
	int sign_1;
	mpanum tmp_dest;
	char mem_marker;

	if (__mpanum_is_zero(op1) || op2 == 0) {
		mpa_set_word(dest, 0);
		return;
	}

	sign_1 = __mpanum_sign(op1);

	/* handle the case when dest is the operand */
	mem_marker = (dest == op1);
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	__mpa_abs_mul_word(tmp_dest, op1, op2);

	if (sign_1 == MPA_NEG_SIGN)
		__mpanum_neg(tmp_dest);
	mpa_copy(dest, tmp_dest);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_dest, pool);
}
