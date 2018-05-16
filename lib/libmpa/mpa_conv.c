// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"

/*------------------------------------------------------------
 *
 *  mpa_set_S32
 *
 */
void mpa_set_S32(mpanum dest, int32_t short_val)
{
#if (MPA_WORD_SIZE == 32)
	if (short_val != 0)
		dest->size = (short_val < 0) ? -1 : 1;
	else
		dest->size = 0;
	dest->d[0] = (short_val < 0) ? -short_val : short_val;
#else
#error "Write code for digit size != 32"
#endif
}

/*------------------------------------------------------------
 *
 *  mpa_get_S32
 *
 *  Returns zero if the src fits within an int32_t
 *  otherwise it returns non-zero and the dest value is undefined.
 */
int32_t mpa_get_S32(int32_t *dest, mpanum src)
{
#if (MPA_WORD_SIZE == 32)
	if (__mpanum_size(src) > 1)
		return -1;
	if (__mpanum_lsw(src) > INT32_MIN && __mpanum_sign(src) == MPA_NEG_SIGN)
		return -1;
	if (__mpanum_lsw(src) > INT32_MAX && __mpanum_sign(src) == MPA_POS_SIGN)
		return -1;

	*dest = __mpanum_get_word(0, src) * __mpanum_sign(src);
	return 0;

#else
#error "Write code for digit size != 32"
#endif
}

/*------------------------------------------------------------
 *
 *  mpa_set_word
 *
 */
void mpa_set_word(mpanum dest, mpa_word_t src)
{
	dest->d[0] = src;
	dest->size = (src == 0) ? 0 : 1;
}

/*------------------------------------------------------------
 *
 *  mpa_get_word
 *
 * Returns the absolute value of the least significant word of src
 */
mpa_word_t mpa_get_word(mpanum src)
{
	return __mpanum_get_word(0, src);
}
