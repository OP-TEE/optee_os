/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020 Linaro Limited
 */

#ifndef __AES_ARMV8_CE_H
#define __AES_ARMV8_CE_H

#include <types_ext.h>

/* Prototypes for assembly functions */
uint32_t ce_aes_sub(uint32_t in);
void ce_aes_invert(void *dst, const void *src);
void ce_aes_ecb_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, int first);
void ce_aes_ecb_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, int first);
void ce_aes_cbc_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, uint8_t iv[]);
void ce_aes_cbc_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, uint8_t iv[]);
void ce_aes_ctr_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, uint8_t ctr[], int first);
void ce_aes_xts_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk1[],
			int rounds, int blocks, uint8_t const rk2[],
			uint8_t iv[]);
void ce_aes_xts_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk1[],
			int rounds, int blocks, uint8_t const rk2[],
			uint8_t iv[]);
void ce_aes_xor_block(uint8_t out[], uint8_t const op1[], uint8_t const op2[]);

#endif /*__AES_ARMV8_CE_H*/
