// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2017-2020, Linaro Limited
 *
 *  NIST SP800-38D compliant GCM implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <crypto/crypto.h>
#include <crypto/internal_aes-gcm.h>
#include <io.h>
#include <kernel/panic.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * See also:
 * [MGV] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/
gcm-revised-spec.pdf
 *
 * We use the algorithm described as Shoup's method with 4-bit tables in
 * [MGV] 4.1, pp. 12-13, to enhance speed without using too much memory.
 */

/*
 * Precompute small multiples of H, that is set
 *      HH[i] || HL[i] = H times i,
 * where i is seen as a field element as in [MGV], ie high-order bits
 * correspond to low powers of P. The result is stored in the same way, that
 * is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
 * corresponds to P^127.
 */
void internal_aes_gcm_ghash_gen_tbl(struct internal_ghash_key *ghash_key,
				    const struct internal_aes_gcm_key *ek)
{
	int i, j;
	uint64_t vl, vh;
	unsigned char h[16];

	memset(h, 0, 16);
	crypto_aes_enc_block(ek->data, sizeof(ek->data), ek->rounds, h, h);

	vh = get_be64(h);
	vl = get_be64(h + 8);

	/* 8 = 1000 corresponds to 1 in GF(2^128) */
	ghash_key->HL[8] = vl;
	ghash_key->HH[8] = vh;

	/* 0 corresponds to 0 in GF(2^128) */
	ghash_key->HH[0] = 0;
	ghash_key->HL[0] = 0;

	for (i = 4; i > 0; i >>= 1) {
		uint32_t T = (vl & 1) * 0xe1000000U;

		vl  = (vh << 63) | (vl >> 1);
		vh  = (vh >> 1) ^ ((uint64_t)T << 32);

		ghash_key->HL[i] = vl;
		ghash_key->HH[i] = vh;
	}

	for (i = 2; i <= 8; i *= 2) {
		uint64_t *HiL = ghash_key->HL + i;
		uint64_t *HiH = ghash_key->HH + i;

		vh = *HiH;
		vl = *HiL;
		for (j = 1; j < i; j++) {
			HiH[j] = vh ^ ghash_key->HH[j];
			HiL[j] = vl ^ ghash_key->HL[j];
		}
	}
}

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t last4[16] = {
	0x0000, 0x1c20, 0x3840, 0x2460,
	0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560,
	0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/*
 * Sets output to x times H using the precomputed tables.
 * x and output are seen as elements of GF(2^128) as in [MGV].
 */
void internal_aes_gcm_ghash_mult_tbl(struct internal_ghash_key *ghash_key,
				     const unsigned char x[16],
				     unsigned char output[16])
{
	int i = 0;
	unsigned char lo = 0, hi = 0, rem = 0;
	uint64_t zh = 0, zl = 0;

	lo = x[15] & 0xf;

	zh = ghash_key->HH[lo];
	zl = ghash_key->HL[lo];

	for (i = 15; i >= 0; i--) {
		lo = x[i] & 0xf;
		hi = x[i] >> 4;

		if (i != 15) {
			rem = (unsigned char)zl & 0xf;
			zl = (zh << 60) | (zl >> 4);
			zh = (zh >> 4);
			zh ^= (uint64_t)last4[rem] << 48;
			zh ^= ghash_key->HH[lo];
			zl ^= ghash_key->HL[lo];
		}

		rem = (unsigned char)zl & 0xf;
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= (uint64_t)last4[rem] << 48;
		zh ^= ghash_key->HH[hi];
		zl ^= ghash_key->HL[hi];
	}

	put_be64(output, zh);
	put_be64(output + 8, zl);
}
