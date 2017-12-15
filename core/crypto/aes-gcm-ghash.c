// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Mike Belopuhov
 * Copyright (c) 2017, Linaro Limited
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <crypto/internal_aes-gcm.h>
#include <kernel/panic.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>

#include "aes-gcm-private.h"

/*
 * gfmul() is based on ghash_gfmul() from
 * https://github.com/openbsd/src/blob/master/sys/crypto/gmac.c
 */
static void gfmul(const uint64_t X[2], const uint64_t Y[2], uint64_t product[2])
{
	uint64_t y[2];
	uint64_t z[2] = { 0 };
	const uint8_t *x = (const uint8_t *)X;
	uint32_t mul;
	size_t n;

	y[0] = TEE_U64_FROM_BIG_ENDIAN(Y[0]);
	y[1] = TEE_U64_FROM_BIG_ENDIAN(Y[1]);

	for (n = 0; n < TEE_AES_BLOCK_SIZE * 8; n++) {
		/* update Z */
		if (x[n >> 3] & (1 << (~n & 7)))
			internal_aes_gcm_xor_block(z, y);

		/* update Y */
		mul = y[1] & 1;
		y[1] = (y[0] << 63) | (y[1] >> 1);
		y[0] = (y[0] >> 1) ^ (0xe100000000000000 * mul);
	}

	product[0] = TEE_U64_TO_BIG_ENDIAN(z[0]);
	product[1] = TEE_U64_TO_BIG_ENDIAN(z[1]);
}

void internal_aes_gcm_ghash_update_block(struct internal_aes_gcm_state *state,
					 const void *data)
{
	void *y = state->hash_state;

	internal_aes_gcm_xor_block(y, data);
	gfmul((void *)state->hash_subkey, y, y);
}
