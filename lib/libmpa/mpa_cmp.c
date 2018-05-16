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

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_cmp
 *
 *  Returns 0  if |op1| == |op2|
 *          >0 if |op1| >  |op2|
 *          <0 if |op1| <  |op2|
 */
int __mpa_abs_cmp(const mpanum op1, const mpanum op2)
{
	int wpos;
	char same;

	/* if they're really the same, return 0 */
	if (op1 == op2)
		return 0;

	/* check the sizes */
	if (__mpanum_size(op1) != __mpanum_size(op2))
		return __mpanum_size(op1) - __mpanum_size(op2);

	if (__mpanum_is_zero(op1) && __mpanum_is_zero(op2))
		return 0;

	/* Ok, so we have the same size and they're not zero. Check words */
	wpos = __mpanum_size(op1) - 1;
	same = 1;
	while (same && (wpos >= 0)) {
		same = (op1->d[wpos] == op2->d[wpos]);
		wpos--;
	}
	if (same)
		return 0;
	wpos++;
	return (op1->d[wpos] > op2->d[wpos] ? 1 : -1);
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_greater_than
 *
 *  Returns 1 if |op1| > |op2| and otherwise returns 0.
 */
int __mpa_abs_greater_than(const mpanum op1, const mpanum op2)
{
	return (__mpa_abs_cmp(op1, op2) > 0 ? 1 : 0);
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_abs_less_than
 *
 *  Returns 1 if |op1| < |op2| and otherwise returns 0.
 */
int __mpa_abs_less_than(const mpanum op1, const mpanum op2)
{
	return (__mpa_abs_cmp(op1, op2) < 0 ? 1 : 0);
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   mpa_cmp
 *
 *  Returns 0  if op1 == op2
 *          >0 if op1 >  op2
 *          <0 if op1 <  op2
 */
int32_t mpa_cmp(const mpanum op1, const mpanum op2)
{
	int sign_1;
	int abscmp;

	/* if they have different signs, it's straight forward */
	sign_1 = __mpanum_sign(op1);
	if (sign_1 != __mpanum_sign(op2))
		return sign_1;

	/* handle the special case where op1->size = 0 */
	if (__mpanum_size(op1) == 0)
		return __mpanum_size(op2) == 0 ? 0 : -__mpanum_sign(op2);

	/* so they have the same sign. compare the abs values and decide
	 * based on sign_1.
	 */

	abscmp = __mpa_abs_cmp(op1, op2);
	if (sign_1 != MPA_POS_SIGN)
		return -abscmp;
	return abscmp;
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_cmp_short
 *
 *  Compares op1 to the word_t op2 and returns:
 *      >0 if op1 > op2,
 *       0 if op1 == op2
 *      <0 if op1 < op2
 */
int32_t mpa_cmp_short(const mpanum op1, int32_t op2)
{
#if (MPA_WORD_SIZE == 32)

	int sign_1;
	int sign_2;
	mpa_word_t op2abs;

	sign_1 = __mpanum_sign(op1);
	sign_2 = (op2 < 0) ? MPA_NEG_SIGN : MPA_POS_SIGN;

	/* handle the special case where op1->size = 0 */
	if (op1->size == 0)
		return op2 == 0 ? 0 : -sign_2;

	/* check if op1 is larger than an int32_t */
	if (__mpanum_size(op1) > 1)
		return sign_1;

	/* check if they have different signs */
	if (sign_1 != sign_2)
		return sign_1;

	/* here they have the same sign and we can compare absolute values */

	op2abs = ((op2 < 0) ? (mpa_word_t) -op2 : (mpa_word_t) op2);

	if (__mpanum_lsw(op1) == op2abs)
		return 0;

	return (__mpanum_lsw(op1) > op2abs) ? sign_1 : -sign_1;

#else
#error "Write code for digit size != 32"
#endif
}
