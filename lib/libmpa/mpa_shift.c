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
 *  __mpa_shift_words_left
 *
 */
void __mpa_shift_words_left(mpanum op, mpa_word_t q)
{
	mpa_word_t i;

	if (q == 0 || __mpanum_is_zero(op))
		return;
	for (i = __mpanum_size(op) + q - 1; i > q - 1; i--)
		op->d[i] = op->d[i - q];

	mpa_memset(op->d, 0, BYTES_PER_WORD * q);

	/* update the size of op */
	if (op->size > 0)
		op->size += q;
	else
		op->size -= q;
}

/*------------------------------------------------------------
 *
 *  __mpa_shift_words_right
 *
 */
void __mpa_shift_words_right(mpanum op, mpa_word_t q)
{
	mpa_word_t i;

	if (q == 0 || __mpanum_is_zero(op))
		return;

	if (q >= __mpanum_size(op)) {
		mpa_set_word(op, 0);
		return;
	}

	for (i = 0; i < __mpanum_size(op) - q; i++)
		op->d[i] = op->d[i + q];

	/* update the size of dest */
	if (op->size > 0)
		op->size -= q;
	else
		op->size += q;
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  mpa_shift_left
 *
 *  Shifts src left by "steps" step and put result in dest.
 *  It does not care about signs. Dest will have same sign as src.
 */
void mpa_shift_left(mpanum dest, mpanum src, mpa_word_t steps)
{
	mpa_word_t q;		/* quotient of steps div WORD_SIZE */
	mpa_word_t r;		/* remainder of steps div WORD_SIZE */
	mpa_word_t i;
	/* the bits of the word which will be shifted into another word */
	mpa_word_t rbits;
	mpa_word_t need_extra_word;

	/*
	 *  Copy first, then check, since even a shifted zero should
	 *  be copied.
	 */
	mpa_copy(dest, src);
	__mpa_set_unused_digits_to_zero(dest);
	if (steps == 0 || __mpanum_is_zero(dest))
		return;

	r = steps & (WORD_SIZE - 1);	/* 0 <= r < WORD_SIZE */
	q = steps >> LOG_OF_WORD_SIZE;	/* 0 <= q */

	/*
	 *  The size of dest will always increase by at least q.
	 *  If we're shifting r bits and the r highest bits in
	 *  the MSW of dest is zero, we don't need the extra word
	 *  Note:
	 *  We cannot do
	 *  if (_mpanumMSW(dest) >> (WORD_SIZE - r))
	 *  since some compilers (MS) does not shift the word
	 *  if the shift quantity is larger or equal to the word size...
	 *  Otherwise it would be natural to say that (a >> b) is just zero
	 *  if b is larger than the number of bit of a, but no no...
	 */
	need_extra_word = 0;

	if (r == 0) {		/* and q > 0 */
		/*
		 *  We have a simple shift by words
		 */
		for (i = __mpanum_size(dest) + q - 1; i > q - 1; i--)
			dest->d[i] = dest->d[i - q];
	} else {
		if (__mpanum_msw(dest) &
		    (((((mpa_word_t)1 << r) - 1u)) << (WORD_SIZE - r)))
			need_extra_word = 1;
		/*
		 * We have a combination of word and bit shifting.
		 *
		 * If need_extra_word is 1, the MSW is special and handled
		 * here
		 */
		i = __mpanum_size(dest) + q + need_extra_word;
		if (need_extra_word) {
			rbits = dest->d[i - q - 1] >> (WORD_SIZE - r);
			dest->d[i] ^= rbits;
		}
		i--;
		dest->d[i] = dest->d[i - q] << r;
		while (i > q) {
			rbits = dest->d[i - q - 1] >> (WORD_SIZE - r);
			dest->d[i] ^= rbits;
			i--;
			dest->d[i] = dest->d[i - q] << r;
		}
	}
	mpa_memset(dest->d, 0, BYTES_PER_WORD * q);
	/* update the size of dest */
	if (dest->size > 0)
		dest->size += q + need_extra_word;
	else
		dest->size -= q + need_extra_word;
}

/*------------------------------------------------------------
 *
 *  mpa_shift_right
 *
 *  Shifts src right by "steps" step and put result in dest.
 *  It does not care about signs. Dest will have same sign as src.
 *
 */
void mpa_shift_right(mpanum dest, mpanum src, mpa_word_t steps)
{
	mpa_word_t q;		/* quotient of steps div WORD_SIZE */
	mpa_word_t r;		/* remainder of steps div WORD_SIZE */
	mpa_word_t i;
	/* the bits of the word which will be shifted into another word */
	mpa_word_t rbits;

	/*
	 *  Copy first, then check, since even a shifted zero should
	 *  be copied.
	 */
	mpa_copy(dest, src);
	__mpa_set_unused_digits_to_zero(dest);
	if (steps == 0 || __mpanum_is_zero(dest))
		return;

	r = steps & (WORD_SIZE - 1);	/* 0 <= r < WORD_SIZE */
	q = steps >> LOG_OF_WORD_SIZE;	/* 0 <= q */

	if (q >= __mpanum_size(dest)) {
		mpa_set_word(dest, 0);
		return;
	}

	/*
	 *  Here we have:
	 *      0 <= r < WORD_SIZE - 1
	 *      0 <= q < _mpanumSize(dest)
	 */
	if (r == 0) {		/* and q > 0 */
		/* Simple shift by words */
		for (i = 0; i < __mpanum_size(dest) - q; i++)
			dest->d[i] = dest->d[i + q];
	} else {
		/* combination of word and bit shifting */
		for (i = 0; i < __mpanum_size(dest) - q - 1; i++) {
			dest->d[i] = dest->d[i + q];
			rbits = dest->d[i + q + 1] & ((1UL << r) - 1);
			dest->d[i] =
			    (dest->d[i] >> r) ^ (rbits << (WORD_SIZE - r));
		}
		/* final word is special */
		dest->d[i] = dest->d[i + q] >> r;
	}

	/* update the size of dest */
	if (dest->size > 0)
		dest->size -= q;
	else
		dest->size += q;

	/* Take care of the case when we shifted out all bits from MSW */
	if (__mpanum_msw(dest) == 0) {
		if (dest->size > 0)
			dest->size--;
		else
			dest->size++;
	}
}
