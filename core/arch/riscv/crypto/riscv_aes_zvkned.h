// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __AES_RISCV_ZVKNED_H
#define __AES_RISCV_ZVKNED_H

#include <types_ext.h>

void riscv_aes_ecb_encrypt(const uint8_t *key, const uint8_t *src,
			   uint8_t *dst, size_t len, unsigned int rounds);
void riscv_aes_ecb_decrypt(const uint8_t *key, const uint8_t *src,
			   uint8_t *dst, size_t len, unsigned int rounds);
void riscv_aes_cbc_encrypt(const uint8_t *key, const uint8_t *src,
			   uint8_t *dst, size_t len, uint8_t iv[16],
			   unsigned int rounds);
void riscv_aes_cbc_decrypt(const uint8_t *key, const uint8_t *src,
			   uint8_t *dst, size_t len, uint8_t iv[16],
			   unsigned int rounds);

#endif /* __AES_RISCV_ZVKNED_H */
