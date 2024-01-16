/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef __CRYPTO_GHASH_CE_CORE_H
#define __CRYPTO_GHASH_CE_CORE_H

#include <inttypes.h>

struct internal_ghash_key {
	uint64_t h[2];
	uint64_t h2[2];
	uint64_t h3[2];
	uint64_t h4[2];
};

void pmull_ghash_update_p64(int blocks, uint64_t dg[2], const uint8_t *src,
			    const struct internal_ghash_key *ghash_key,
			    const uint8_t *head);
void pmull_ghash_update_p8(int blocks, uint64_t dg[2], const uint8_t *src,
			   const struct internal_ghash_key *ghash_key,
			   const uint8_t *head);

void pmull_gcm_load_round_keys(const uint64_t rk[30], int rounds);

void pmull_gcm_encrypt(int blocks, uint64_t dg[2], uint8_t dst[],
		       const uint8_t src[],
		       const struct internal_ghash_key *ghash_key,
		       uint64_t ctr[], const uint64_t rk[], int rounds,
		       uint8_t ks[]);


void pmull_gcm_decrypt(int blocks, uint64_t dg[2], uint8_t dst[],
		       const uint8_t src[],
		       const struct internal_ghash_key *ghash_key,
		       uint64_t ctr[], const uint64_t rk[], int rounds);

uint32_t pmull_gcm_aes_sub(uint32_t input);

void pmull_gcm_encrypt_block(uint8_t dst[], const uint8_t src[], int rounds);

#endif /*__CRYPTO_GHASH_CE_CORE_H*/
