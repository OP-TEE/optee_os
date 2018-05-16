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
 *  Function:   __mpa_full_adder
 *
 *  A word_t sized full adder. Incoming carry is in *carry.
 *  The sum will be put in *sum and the
 *  outgoing carry will be returned in *carry
 */
void __mpa_full_adder(mpa_word_t a,
		      mpa_word_t b, mpa_word_t *sum, mpa_word_t *carry)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t _s;
	_s = (mpa_dword_t) (a) + (mpa_dword_t) (b) + (mpa_dword_t) (*carry);
	*sum = (mpa_word_t) (_s);
	*carry = ((mpa_word_t) (_s >> MPA_WORD_SIZE));
#else
	*sum = a + *carry;
	*carry = (*sum < a);
	*sum += b;
	*carry += (*sum < b);
#endif
}

/*  --------------------------------------------------------------------
 *   Function:   __mpa_full_sub
 *
 *   A word_t sized full subtraction function. Incoming carry is in *carry.
 *   The difference will be put in *diff and the outgoing carry will be returned
 *   in *carry.
 */
void __mpa_full_sub(mpa_word_t a,
		    mpa_word_t b, mpa_word_t *diff, mpa_word_t *carry)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t _d;
	_d = (mpa_dword_t) (a) - (mpa_dword_t) (b) - (mpa_dword_t) (*carry);
	*diff = (mpa_word_t) (_d);
	*carry = 0 - (mpa_word_t) (_d >> WORD_SIZE);
#else
	mpa_word_t _d;
	*diff = a - *carry;
	*carry = (*diff > a);
	_d = *diff - b;
	*carry += (_d > *diff);
	*diff = _d;
#endif
}

/*------------------------------------------------------------
 *
 *  __mpa_full_adder_ackum
 *
 *  A word_t sized full adder with ackumulate. *d  = *d + e + *carry
 *  Outgoing carry is in *carry
 */
void __mpa_full_adder_ackum(mpa_word_t *d, mpa_word_t e, mpa_word_t *carry)
{
#if defined(MPA_SUPPORT_DWORD_T)
	mpa_dword_t _s;
	_s = (mpa_dword_t) (*d) + (mpa_dword_t) (e) + (mpa_dword_t) (*carry);
	*d = (mpa_word_t) (_s);
	*carry = ((mpa_word_t) (_s >> MPA_WORD_SIZE));
#else
	mpa_word_t _s;
	_s = *d + *carry;
	*carry = (_s < *d);
	*d = _s + e;
	*carry += (*d < _s);
#endif
}

#endif /* of USR_ARM_ASM */

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_add
 *
 *  Calculate |op1| + |op2|.
 *  op1 and op2 are pointers to word_t arrays holding the value.
 *  *Sum must be big enough to hold the result.
 */
void __mpa_abs_add(mpa_word_t *sum,
		   mpa_usize_t *sum_size,
		   const mpa_word_t *op1,
		   mpa_usize_t op1_size,
		   const mpa_word_t *op2, mpa_usize_t op2_size)
{
	const mpa_word_t *smaller;
	const mpa_word_t *larger;
	mpa_word_t *sum_begin;
	mpa_usize_t smaller_wsize;	/* size in words of the smallest */
	mpa_usize_t larger_wsize;	/* size in words of the largest */
	mpa_word_t carry;
	mpa_usize_t i;

	/* make sure we know which is the larger one */
	if (op1_size > op2_size) {
		larger = op1;
		smaller = op2;
		larger_wsize = op1_size;
		smaller_wsize = op2_size;
	} else {		/* op2 is the larger or same size */
		larger = op2;
		smaller = op1;
		larger_wsize = op2_size;
		smaller_wsize = op1_size;
	}

	sum_begin = sum;
	carry = 0;
	i = 0;
	while (i < smaller_wsize) {
		__mpa_full_adder(*(smaller++), *(larger++), sum++, &carry);
		i++;
	}
	while (carry && (i < larger_wsize)) {
		__mpa_full_adder(0, *(larger++), sum++, &carry);
		i++;
	}

	if (i < larger_wsize) {
		/* carry did not propagate all the way, copy the rest */
		mpa_memcpy(sum, larger, WORDS_TO_BYTES(larger_wsize - i));
		sum += larger_wsize - i;
	}

	if (carry != 0)
		*(sum++) = carry;
	*sum_size = (mpa_word_t) (sum - sum_begin);
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_add_ackum
 *
 *  Calculate dest = dest + src. Both dest and src must be positive
 *  dest must be big enough to hold the result.
 */
void __mpa_abs_add_ackum(mpanum dest, const mpanum src)
{
	const mpa_word_t *sdig;	/* source digits */
	mpa_word_t *ddig;	/* dest digits */
	mpa_word_t *dest_begin;

	mpa_word_t carry;
	mpa_usize_t i;

	i = src->size - dest->size;
	if (i <= 0)
		i = 0;
	mpa_memset(dest->d + dest->size, 0, (1 + i) * BYTES_PER_WORD);

	dest_begin = dest->d;
	sdig = src->d;
	ddig = dest->d;
	i = 0;
	carry = 0;
	while (i < src->size) {
		__mpa_full_adder_ackum(ddig++, *(sdig++), &carry);
		/*
		 * _s = (mpa_dword_t)*(ddig) + (mpa_dword_t)*(sdig++) +
		 *	(mpa_dword_t)carry;
		 * *(ddig++) = (mpa_word_t)(_s);
		 * carry = (mpa_word_t)(_s >> WORD_SIZE);
		 */
		i++;
	}
	while (carry) {
		__mpa_full_adder_ackum(ddig++, 0, &carry);
		/*
		 * _s = (mpa_dword_t)*(ddig) + (mpa_dword_t)carry;
		 * *(ddig++) = (mpa_word_t)(_s);
		 * carry = (mpa_word_t)(_s >> WORD_SIZE);
		 */
	}
	i = (mpa_word_t) (ddig - dest_begin);
	if (i > dest->size)
		dest->size = i;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_sub
 *
 *  Calculate |op1| - |op2|, where  |op1| >= |op2| must hold.
 *  op1 and op2 are pointers to word_t arrays holding the value.
 *  *Diff must be big enough to hold the result. diff_size is
 *  updated with the number of significant words in *diff.
 */
void __mpa_abs_sub(mpa_word_t *diff,
		   mpa_usize_t *diff_size,
		   const mpa_word_t *op1,
		   mpa_usize_t op1_size,
		   const mpa_word_t *op2, mpa_usize_t op2_size)
{
	mpa_word_t carry;
	mpa_usize_t i;

	carry = 0;
	i = 0;
	while (i < op2_size) {
		__mpa_full_sub(*(op1++), *(op2++), diff++, &carry);
		i++;
	}
	/*
	 * Here we have no more digits in op2, we only need to keep on
	 * subtracting 0 from op1, and deal with carry.
	 */
	while (carry && (i < op1_size)) {
		__mpa_full_sub(*(op1++), 0, diff++, &carry);
		i++;
	}

	if (i < op1_size) {
		/*
		 * Carry did not propagate all the way, now we only need to
		 * copy the rest.
		 */
		mpa_memcpy(diff, op1, WORDS_TO_BYTES(op1_size - i));
		diff += op1_size - i;
	}
	/* check size of diff */
	i = op1_size;
	while ((i > 0) && (*(--diff) == 0))
		i--;
	*diff_size = i;
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   mpa_add
 *
 *  Adds op1 and op2 and puts the result in dest. Dest could be one of the
 *  operands.
 */
void mpa_add(mpanum dest,
	     const mpanum op1, const mpanum op2, mpa_scratch_mem pool)
{
	int sign_1;
	int sign_2;
	mpa_word_t size_1;
	mpa_word_t size_2;
	mpanum tmp_dest;
	int mem_marker;

	size_1 = __mpanum_size(op1);
	size_2 = __mpanum_size(op2);

	sign_1 = __mpanum_sign(op1);
	sign_2 = __mpanum_sign(op2);

	/* Handle the case when dest is one of the operands */
	mem_marker = ((dest == op1) || (dest == op2));
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	/*  Check if we must do a subtraction or a addition.
	 *  Remember, we're not allowed to modify op1 or op2.
	 */

	if (sign_1 == sign_2) {	/* same signs */
		/* tmp_dest = |op1| + |op2|  or tmp_dest = -(|op1| + |op2|) */
		__mpa_abs_add(tmp_dest->d, &(tmp_dest->size), op1->d, size_1,
			      op2->d, size_2);

		if (sign_1 == MPA_NEG_SIGN)
			__mpanum_neg(tmp_dest);

	} else {		/* different signs */
		if (sign_1 == MPA_POS_SIGN) {	/* op1 positive, op1 + (-op2) */
			if (__mpa_abs_greater_than(op1, op2)) {
				/* |op1| > |op2| */

				/* tmp_dest = |op1| - |op2| */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op1->d, size_1, op2->d, size_2);

			} else {	/* |op2| >= |op1| */
				/* tmp_dest = - ( |op2| - |op1|) */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op2->d, size_2, op1->d, size_1);
				__mpanum_neg(tmp_dest);
			}

		} else {	/* op2 positive, (-op1) + op2 */
			if (__mpa_abs_greater_than(op1, op2)) {
				/* |op1| > |op2| */

				/* tmp_dest = - (|op1| - |op2|) */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op1->d, size_1, op2->d, size_2);
				__mpanum_neg(tmp_dest);
			} else {	/* |op2| >= |op1| */
				/* tmp_dest = |op2| - |op1| */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op2->d, size_2, op1->d, size_1);
			}
		}
	}

	mpa_copy(dest, tmp_dest);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_dest, pool);
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_sub
 *
 *  Calculated op1 - op2 and stores the result in dest. Dest could be one of
 *  the operands.
 */
void mpa_sub(mpanum dest,
	     const mpanum op1, const mpanum op2, mpa_scratch_mem pool)
{
	int sign_1;
	int sign_2;
	mpa_word_t size_1;
	mpa_word_t size_2;
	mpanum tmp_dest;
	int mem_marker;

	size_1 = __mpanum_size(op1);
	size_2 = __mpanum_size(op2);

	sign_1 = __mpanum_sign(op1);
	sign_2 = __mpanum_sign(op2);

	/* Handle the case when dest is one of the operands */
	mem_marker = ((dest == op1) || (dest == op2));
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	/*
	 * Check if we must do a subtraction or a addition. Remember,
	 * we're not allowed to modify op1 or op2.
	 */
	if (sign_1 == sign_2) {	/* same signs */
		if (sign_1 == MPA_POS_SIGN) {	/* both positive, op1 - op2 */
			if (__mpa_abs_greater_than(op1, op2)) {
				/* |op1| > |op2| */

				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op1->d, size_1, op2->d, size_2);
			} else {	/* |op1| <= |op2| */
				/* tmp_dest = - (|op2| - |op1|) */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op2->d, size_2, op1->d, size_1);
				__mpanum_neg(tmp_dest);
			}
		} else {
			/* both negative, (-op1) - (-op2) = -(op1 - op2) */

			if (__mpa_abs_greater_than(op1, op2)) {
				/* |op1| > |op2| */

				/* tmp_dest = -(|op1| - |op2|) */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op1->d, size_1, op2->d, size_2);
				__mpanum_neg(tmp_dest);
			} else {	/* |op1| <= |op2| */
				/* tmp_dest = |op2| - |op1| */
				__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size),
					      op2->d, size_2, op1->d, size_1);
			}
		}
	} else {		/* different signs */
		if (sign_1 == MPA_POS_SIGN) {	/* op1 positive, op1 - (-op2) */
			/* tmp_dest = |op1| + |op2| */
			__mpa_abs_add(tmp_dest->d, &(tmp_dest->size), op1->d,
				      size_1, op2->d, size_2);
		} else {	/* op2 positive, (-op1) - op2 = - (op1 + op2) */
			/* tmp_dest = -(|op1| + |op2|) */
			__mpa_abs_add(tmp_dest->d, &(tmp_dest->size), op1->d,
				      size_1, op2->d, size_2);
			__mpanum_neg(tmp_dest);
		}
	}

	mpa_copy(dest, tmp_dest);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_dest, pool);
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_neg
 *
 *  Assigns dest the value of src, but with a change of sign. Dest and src
 *  could be the same variable.
 */
void mpa_neg(mpanum dest, const mpanum src)
{
	mpa_copy(dest, src);
	__mpanum_neg(dest);
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_add_word
 *
 *  Add a word_t (op2) to op1 and put result in dest
 */
void mpa_add_word(mpanum dest,
		 const mpanum op1, mpa_word_t op2, mpa_scratch_mem pool)
{
	int sign_1;
	mpanum tmp_dest;
	mpa_word_t size_1;
	int mem_marker;

	if (op2 == 0) {
		mpa_copy(dest, op1);
		return;
	}

	if (__mpanum_is_zero(op1)) {
		dest->size = 1;
		dest->d[0] = op2;
		return;
	}

	sign_1 = __mpanum_sign(op1);
	size_1 = __mpanum_size(op1);

	/* handle the case when dest is the operand */
	mem_marker = (dest == op1);
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	/* find out if we should do an add or a sub, op2 is always positive */
	if (sign_1 == MPA_POS_SIGN) {	/* add */
		/* tmp_dest = |op1| + op2 */
		__mpa_abs_add(tmp_dest->d, &(tmp_dest->size), op1->d, size_1,
			      &op2, 1);
	} else {		/* sub, op1 is negative: (-op1) + op2 */
		if (__mpanum_size(op1) > 1 || __mpanum_lsw(op1) > op2) {
			/* |op1| > |op2| */

			/* tmp_dest = - (|op1| - op2) */
			__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size), op1->d,
				      size_1, &op2, 1);
			__mpanum_neg(tmp_dest);
		} else {	/* op2 >= |op1| */
			/* tmp_dest = op2 - |op1| */
			tmp_dest->d[0] = op2 - op1->d[0];
			tmp_dest->size = (tmp_dest->d[0] == 0) ? 0 : 1;
		}
	}

	mpa_copy(dest, tmp_dest);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_dest, pool);
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_sub_word
 *
 *  Calculate op1 - op2, op2 is a word_t and always positive.
 */
void mpa_sub_word(mpanum dest,
		 const mpanum op1, mpa_word_t op2, mpa_scratch_mem pool)
{
	int sign_1;
	mpanum tmp_dest;
	mpa_word_t size_1;
	char mem_marker;

	if (op2 == 0) {
		mpa_copy(dest, op1);
		return;
	}

	if (__mpanum_is_zero(op1)) {
		dest->size = -1;
		dest->d[0] = op2;
		return;
	}

	sign_1 = __mpanum_sign(op1);
	size_1 = __mpanum_size(op1);

	/* handle the case when dest is the operand */
	mem_marker = (dest == op1);
	if (mem_marker)
		mpa_alloc_static_temp_var(&tmp_dest, pool);
	else
		tmp_dest = dest;

	/*
	 * Find out if we should do an add or a sub, op2 is always positive
	 *
	 *  dest = op1 - op2        if op1 > op2 >= 0
	 *  dest = -(op2 - op1)     if op2 >= op1 >= 0
	 *  dest = -(|op1| + op2)   if op1 < 0
	 *
	 */
	if (sign_1 == MPA_POS_SIGN) {
		if (__mpanum_size(op1) > 1 || __mpanum_lsw(op1) > op2) {
			__mpa_abs_sub(tmp_dest->d, &(tmp_dest->size), op1->d,
				      size_1, &op2, 1);
		} else {
			tmp_dest->d[0] = op2 - op1->d[0];
			tmp_dest->size = (tmp_dest->d[0] == 0) ? 0 : -1;
		}
	} else {
		__mpa_abs_add(tmp_dest->d, &(tmp_dest->size), op1->d, size_1,
			      &op2, 1);
		__mpanum_neg(tmp_dest);
	}

	mpa_copy(dest, tmp_dest);
	if (mem_marker)
		mpa_free_static_temp_var(&tmp_dest, pool);
}
