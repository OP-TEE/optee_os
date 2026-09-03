/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __RISCV_AES_ZVKNED_ZVKB_H
#define __RISCV_AES_ZVKNED_ZVKB_H

#include <types_ext.h>

/*
 * @key points at the expanded schedule produced by
 * crypto_accel_aes_expand_keys(), @len is a non-zero whole number of AES
 * blocks and @rounds is 10, 12 or 14. @ctr is a 16-byte big-endian counter
 * block, advanced by one per AES block over its full 128 bits and written
 * back so the stream can be continued. The caller owns the vector unit for
 * the duration of the call.
 */
void riscv_aes_ctr_be_encrypt(const void *key, const void *src, void *dst,
			      size_t len, void *ctr, unsigned int rounds);

#endif /* __RISCV_AES_ZVKNED_ZVKB_H */
