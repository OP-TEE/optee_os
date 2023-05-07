/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef __SM4_ARMV8_CE_H
#define __SM4_ARMV8_CE_H

#include <types_ext.h>

/* Prototypes for assembly functions */
void ce_sm4_setkey_enc(uint32_t sk[32], uint8_t const key[16]);
void ce_sm4_setkey_dec(uint32_t sk[32], uint8_t const key[16]);
void ce_sm4_ecb_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			size_t len);
void ce_sm4_cbc_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			size_t len, uint8_t iv[]);
void ce_sm4_cbc_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			size_t len, uint8_t iv[]);
void ce_sm4_ctr_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			size_t len, uint8_t iv[]);
void ce_sm4_xts_encrypt(uint8_t out[], uint8_t const in[],
			uint8_t const rk1[], uint8_t const rk2[], size_t len,
			uint8_t iv[]);
void ce_sm4_xts_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk1[],
			uint8_t const rk2[], size_t len, uint8_t iv[]);

#endif /*__SM4_ARMV8_CE_H*/
