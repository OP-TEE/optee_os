/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __RISCV_AES_ZVKNED_H
#define __RISCV_AES_ZVKNED_H

#include <types_ext.h>

/*
 * @key points at the expanded schedule produced by
 * crypto_accel_aes_expand_keys(), which is shared with the other modes and
 * is not part of this file. @len is a non-zero whole number of AES
 * blocks and @rounds is 10, 12 or 14. The caller owns the vector unit for
 * the duration of the call.
 */
void riscv_aes_ecb_encrypt(const void *key, const void *src, void *dst,
			   size_t len, unsigned int rounds);
void riscv_aes_ecb_decrypt(const void *key, const void *src, void *dst,
			   size_t len, unsigned int rounds);

/* As above, and @iv is the chaining value, updated in place */
void riscv_aes_cbc_encrypt(const void *key, const void *src, void *dst,
			   size_t len, void *iv, unsigned int rounds);
void riscv_aes_cbc_decrypt(const void *key, const void *src, void *dst,
			   size_t len, void *iv, unsigned int rounds);

#endif /* __RISCV_AES_ZVKNED_H */
