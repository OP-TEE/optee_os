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
#include <tee_api_types.h>

static random_generator_cb get_rng_array;

void mpa_set_random_generator(random_generator_cb callback)
{
	get_rng_array = callback;
}

static uint8_t get_random_byte(void)
{
	uint8_t buf;
	while (get_rng_array(&buf, 1) != TEE_SUCCESS)
	;

	return buf;
}

/*------------------------------------------------------------
 *
 *  mpa_get_random
 *
 */
void mpa_get_random(mpanum dest, mpanum limit)
{
	int done = 0;

	mpa_wipe(dest);
	if (__mpanum_alloced(dest) < __mpanum_size(limit))
		dest->size = __mpanum_alloced(dest);
	else
		dest->size = __mpanum_size(limit);
	while (!done) {
		for (int idx = 0; idx < dest->size; idx++) {
			mpa_word_t w = 0;
			for (int j = 0; j < BYTES_PER_WORD; j++)
				w = (w << 8) ^ get_random_byte();
			dest->d[idx] = w;
		}
		if (dest->size < __mpanum_size(limit)) {
			done = 1;
		} else {
			mpa_word_t hbi =
			    (mpa_word_t) mpa_highest_bit_index(limit);
			/* 1 <= hbi <= WORD_SIZE */
			hbi = (hbi % WORD_SIZE) + 1;
			if (hbi < WORD_SIZE) {
				hbi = (1 << hbi) - 1;
				dest->d[dest->size - 1] &= hbi;
			}
			done = (mpa_cmp(dest, limit) < 0) ? 1 : 0;
		}
	}
}

int mpa_get_random_digits(mpanum dest, mpa_usize_t size)
{
	mpa_wipe(dest);

	if (size > __mpanum_alloced(dest))
		return 0;

	dest->size = size;

	if (get_rng_array(&dest->d, WORDS_TO_BYTES(__mpanum_size(dest))))
		return 0;

	return __mpanum_size(dest);
}
