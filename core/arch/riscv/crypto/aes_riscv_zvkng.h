/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#ifndef __RISCV_AES_ZVKNG_H
#define __RISCV_AES_ZVKNG_H

#include <stddef.h>
#include <stdint.h>
#include <utee_defines.h>
#include <util.h>

/*
 * ABI expected by the Linux vector AES routines: encryption schedule,
 * decryption schedule, then the original key length at byte offset 480.
 */
struct riscv_aes_key {
	uint8_t enc_key[15][TEE_AES_BLOCK_SIZE];
	uint8_t dec_key[15][TEE_AES_BLOCK_SIZE];
	uint32_t key_len;
} __aligned(16);

void aes_ecb_encrypt_zvkned(const struct riscv_aes_key *key,
			    const void *in, void *out, size_t len);
void aes_xts_encrypt_zvkned_zvbb_zvkg(const struct riscv_aes_key *key,
				      const void *in, void *out, size_t len,
				      void *tweak);
void aes_xts_decrypt_zvkned_zvbb_zvkg(const struct riscv_aes_key *key,
				      const void *in, void *out, size_t len,
				      void *tweak);

#endif /*__RISCV_AES_ZVKNG_H*/
