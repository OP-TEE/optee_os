// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <crypto/ghash-ce-core.h>
#include <io.h>
#include <tomcrypt_arm_neon.h>
#include <tomcrypt.h>
#include <utee_defines.h>

/**
  GCM multiply by H
  @param gcm   The GCM state which holds the H value
  @param I     The value to multiply H by
 */
void gcm_mult_h(gcm_state *gcm, unsigned char *I)
{
	struct tomcrypt_arm_neon_state state;
	const uint8_t zeroes[TEE_AES_BLOCK_SIZE] = { 0 };
	uint64_t k[2];
	uint64_t a;
	uint64_t b;
	uint64_t dg[2];

	b = get_be64(gcm->H);
	a = get_be64(gcm->H + 8);

	k[0] = (a << 1) | (b >> 63);
	k[1] = (b << 1) | (a >> 63);
	if (b >> 63)
		k[1] ^= 0xc200000000000000UL;

	dg[1] = get_be64(I);
	dg[0] = get_be64(I + 8);

	tomcrypt_arm_neon_enable(&state);
#ifdef _CFG_CORE_LTC_HWSUPP_PMULL
	pmull_ghash_update_p64(1, dg, zeroes, k, NULL);
#else
	pmull_ghash_update_p8(1, dg, zeroes, k, NULL);
#endif
	tomcrypt_arm_neon_disable(&state);

	put_be64(I, dg[1]);
	put_be64(I + 8, dg[0]);
}

