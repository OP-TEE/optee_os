// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"
#include <tee_api_types.h>

/*
 * This code is compiled for both kernel and user mode. How to obtain
 * random differs since the RNG resides in kernel mode.
 */
#ifdef __KERNEL__
#include <crypto/crypto.h>

static TEE_Result get_rng_array(void *buf, size_t blen)
{
	return crypto_rng_read(buf, blen);
}
#else
#include "utee_syscalls.h"

static TEE_Result get_rng_array(void *buf, size_t blen)
{
	return utee_cryp_random_number_generate(buf, blen);
}
#endif

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
