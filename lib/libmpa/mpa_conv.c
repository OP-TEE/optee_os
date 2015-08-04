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
