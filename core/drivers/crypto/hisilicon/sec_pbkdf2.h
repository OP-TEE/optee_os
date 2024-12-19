/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022-2024 HiSilicon Limited. */

#ifndef __SEC_PBKDF2_H__
#define __SEC_PBKDF2_H__

#define SEC_MAX_SALT_LEN		1024
#define SEC_MAX_PASSWORD_LEN		128
#define SEC_MAX_DK_LEN			512
#define SEC_MAX_ITERATION_NUM		16777215
#define SEC_HMAC_SHA1			0x10
#define SEC_HMAC_SHA256			0x11
#define SEC_HMAC_SHA224			0x13
#define SEC_HMAC_SHA384			0x14
#define SEC_HMAC_SHA512			0x15
#define SEC_HMAC_SM3			0x26
#define SEC_HUK_ENABLE			0x1
#define SEC_IMG_ROTKEY_AP		0x6
#define SEC_CRITICAL_ITERATION_NUM	1000000
#define SEC_PER_BLOCK_TIME1_NS		(3 * 48)
#define SEC_PER_BLOCK_TIME2_NS		(3 * 68)
#define SEC_MAX_TIMEOUT_NS		4000000000

struct sec_pbkdf2_msg {
	uint8_t salt[SEC_MAX_SALT_LEN];
	uint8_t base_key[SEC_MAX_PASSWORD_LEN];
	uint8_t out[SEC_MAX_DK_LEN];
	uintptr_t salt_dma;
	uintptr_t key_dma;
	uintptr_t out_dma;
	uint32_t salt_len;
	uint32_t key_len;
	uint32_t out_len;
	uint32_t c_num;
	uint32_t derive_type;
};

#endif
