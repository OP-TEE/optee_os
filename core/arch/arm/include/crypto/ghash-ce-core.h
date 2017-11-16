/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __GHASH_CE_CORE_H
#define __GHASH_CE_CORE_H

#include <inttypes.h>

void pmull_ghash_update_p64(int blocks, uint64_t dg[2], const uint8_t *src,
			    const uint64_t k[2], const uint8_t *head);
void pmull_ghash_update_p8(int blocks, uint64_t dg[2], const uint8_t *src,
			   const uint64_t k[2], const uint8_t *head);

void pmull_gcm_load_round_keys(uint64_t rk[30], int rounds);

void pmull_gcm_encrypt(int blocks, uint64_t dg[2], uint8_t dst[],
		       const uint8_t src[], const uint64_t k[2],
		       uint64_t ctr[], int rounds, uint8_t ks[]);


void pmull_gcm_decrypt(int blocks, uint64_t dg[2], uint8_t dst[],
		       const uint8_t src[], const uint64_t k[2],
		       uint64_t ctr[], int rounds);

void pmull_gcm_encrypt_block(uint8_t dst[], const uint8_t src[], int rounds);

#endif /*__GHASH_CE_CORE_H*/
