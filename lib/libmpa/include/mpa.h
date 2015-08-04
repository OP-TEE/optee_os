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
#ifndef GUARD_MPA_H
#define GUARD_MPA_H

#include "mpalib.h"

/************************************************************************\
 *  MACRO DEFINITIONS
\************************************************************************/

#define WORD_SIZE               MPA_WORD_SIZE
#define BYTES_PER_WORD          (MPA_WORD_SIZE >> 3)
#define NIBBLES_PER_WORD        (MPA_WORD_SIZE >> 2)
#define LOG_OF_WORD_SIZE        MPA_LOG_OF_WORD_SIZE
#define LOG_OF_BYTES_PER_WORD   MPA_LOG_OF_BYTES_PER_WORD
#define WORD_ALL_BITS_ONE       ((mpa_word_t)-1)

/* number of bytes to hold x bits, x must be positive integer */
#define BITS_TO_BYTES(x) (((x)+7) >> 3)
/* convert from bytes to bits */
#define BYTES_TO_BITS(x) ((x) << 3)

/* convert from words to bytes */
#define WORDS_TO_BYTES(x) ((x) << LOG_OF_BYTES_PER_WORD)
/* convert from bytes to minimum number of words needed to hold x bytes */
#define BYTES_TO_WORDS(x) (((x) + BYTES_PER_WORD - 1) >> LOG_OF_BYTES_PER_WORD)

/* convert from bits to words and vice versa */
#define WORDS_TO_BITS(x) ((x) * MPA_WORD_SIZE)
#define BITS_TO_WORDS(x) (((x) + MPA_WORD_SIZE - 1) / MPA_WORD_SIZE)

#define __MAX(a, b) ((a) < (b) ? (b) : (a))
#define __MIN(a, b) ((a) < (b) ? (a) : (b))

/* macros to access internal variables in a mpa_numbase */

#define MPA_NEG_SIGN -1
#define MPA_POS_SIGN  1

#define __mpanum_alloced(x) ((x)->alloc)
#define __mpanum_size(x) ((mpa_usize_t)((x)->size >= 0 ? \
				(x)->size : -(x)->size))
#define __mpanum_sign(x) ((x)->size >= 0 ? MPA_POS_SIGN : MPA_NEG_SIGN)

/* macros to set internal variables in mpa_numbase */

/* SetSign take either MPA_POS_SIGN or MPA_NEG_SIGN as argument */
#define __mpanum_set_sign(x, s) \
	do { \
		if (__mpanum_sign(x) != (s)) \
			(x)->size = -(x)->size; \
	} while (0)
#define __mpanum_is_zero(x) ((x)->size == 0)
#define __mpanum_neg(x) ((x)->size = -((x)->size))

/* Get most significant word of x, call only on non-zero x */
#define __mpanum_msw(x) ((x)->d[__mpanum_size(x)-1])
#define __mpanum_lsw(x) ((x)->d[0])

/* Get word idx of x, if idx >= size, return 0
 * This macro is used in the montgomery multiplication to allow
 * operands to have shorter alloc than n
 */
#define __mpanum_get_word(idx, x) ((idx >= __mpanum_size(x)) ? \
					0 : ((x)->d[idx]))

/* n = 0..NIBBLES_PER_WORD-1 */
#if defined(MPA_LITTLE_ENDIAN)
#define NIBBLE_OF_WORD(n, w) (((w) >> ((n) << 2)) & 0xf)
#elif defined(MPA_BIG_ENDIAN)
#define NIBBLE_OF_WORD(n, w) (((w) >> ((7-(n)) << 2)) & 0xf)
#else
#error "You must define either MPA_LITTLE_ENDIAN or MPA_BIG_ENDIAN, see mpalib_config.h"
#endif

/* In order to avoid warnings on unused arguments */
#ifndef IDENTIFIER_NOT_USED
#define IDENTIFIER_NOT_USED(x) (void)(&x)
#endif

/*
 * Is NULL defined?
 */
#if !defined(NULL)
#define NULL (void *)0
#endif

/*************************************************************
 *
 *   GLOBAL CONSTANTS AND VARIABLES
 *
 *************************************************************/

/*
 * defined in mpa_misc.c
 */
extern const mpa_num_base const_largest_deci_base;
extern const mpa_num_base Const_1_LShift_Base;
extern const mpa_num_base const_one;

/*************************************************************
 *
 *   INTERNAL FUNCTIONS
 *
 *************************************************************/

/*------------------------------------------------------------
 *
 *  From mpa_mem_static.
 *
 */

/*------------------------------------------------------------
 *
 *  From mpa_addsub.c
 *
 */
void __mpa_full_adder(mpa_word_t a,
		      mpa_word_t b, mpa_word_t *sum, mpa_word_t *carry);

void __mpa_full_sub(mpa_word_t a,
		    mpa_word_t b, mpa_word_t *diff, mpa_word_t *carry);

void __mpa_full_adder_ackum(mpa_word_t *d, mpa_word_t e, mpa_word_t *carry);

void __mpa_abs_add(mpa_word_t *sum,
		   mpa_usize_t *sum_size,
		   const mpa_word_t *op1,
		   mpa_usize_t op1_size,
		   const mpa_word_t *op2, mpa_usize_t op2_size);

void __mpa_abs_add_ackum(mpanum dest, const mpanum src);

void __mpa_abs_sub(mpa_word_t *diff,
		   mpa_usize_t *diff_size,
		   const mpa_word_t *op1,
		   mpa_usize_t op1_size,
		   const mpa_word_t *op2, mpa_usize_t op2_size);

/*------------------------------------------------------------
 *
 *  From mpa_cmp.c
 *
 */

int __mpa_abs_cmp(const mpanum op1, const mpanum op2);

int __mpa_abs_greater_than(const mpanum op1, const mpanum op2);

int __mpa_abs_less_than(const mpanum op1, const mpanum op2);

/*------------------------------------------------------------
 *
 *  From mpa_mul.c
 *
 */
void __mpa_mul_add_word(mpa_word_t a,
			mpa_word_t b, mpa_word_t *p, mpa_word_t *carry);

void __mpa_mul_add_word_cum(mpa_word_t a,
			    mpa_word_t b, mpa_word_t *p, mpa_word_t *carry);

void __mpa_abs_mul_word(mpanum dest, const mpanum op1, mpa_word_t op2);

void __mpa_abs_mul(mpanum dest, const mpanum op1, const mpanum op2);

/*------------------------------------------------------------
 *
 *  From mpa_div.c
 *
 */

mpa_word_t __mpa_div_dword(mpa_word_t n0,
			   mpa_word_t n1, mpa_word_t d, mpa_word_t *r);

void __mpa_div_q_r_internal_word(mpanum q,
				 mpanum r,
				 const mpanum op1, const mpa_word_t op2);

void __mpa_div_q_r(mpanum q,
		   mpanum r,
		   const mpanum op1, const mpanum op2, mpa_scratch_mem pool);

/*------------------------------------------------------------
 *
 *  From mpa_shift.c
 *
 */

void __mpa_shift_words_left(mpanum op, mpa_word_t q);
void __mpa_shift_words_right(mpanum op, mpa_word_t q);

/*------------------------------------------------------------
 *
 *  From mpa_montgomery.c
 *
 */

void __mpa_montgomery_sub_ack(mpanum dest, mpanum src);

void __mpa_montgomery_mul_add(mpanum dest, mpanum src, mpa_word_t w);

void __mpa_montgomery_mul(mpanum dest,
			  mpanum op1, mpanum op2, mpanum n, mpa_word_t n_inv);

/*------------------------------------------------------------
 *
 *  From mpa_misc.c
 *
 */
void __mpa_set_unused_digits_to_zero(mpanum n);

#endif /* include guard */
