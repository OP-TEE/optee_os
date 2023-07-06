/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, HiSilicon Limited
 */
#ifndef __HISI_CIPHER_H__
#define __HISI_CIPHER_H__

#include <drvcrypt.h>
#include <drvcrypt_cipher.h>

enum C_ALG {
	C_ALG_DES = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES = 0x2,
	C_ALG_SM4 = 0x3,
};

enum C_MODE {
	C_MODE_ECB = 0x0,
	C_MODE_CBC,
	C_MODE_CFB,
	C_MODE_OFB,
	C_MODE_CTR,
	C_MODE_CCM,
	C_MODE_GCM,
	C_MODE_XTS,
	C_MODE_CBC_CS = 0x9,
};

#define DES_KEY_SIZE 8
#define SEC_3DES_2KEY_SIZE (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE (3 * DES_KEY_SIZE)
#define SEC_SM4_XTS_KEY_SIZE 32
#define SEC_SM4_ECB_KEY_SIZE 16
#define SEC_MAX_CIPHER_KEY_SIZE 64
#define MAX_CIPHER_LENGTH 16776704
#define MIN_CIPHER_LENGTH 16

#define DES_CBC_IV_SIZE 8
#define AES_SM4_IV_SIZE 16
#define SEC_MAX_IV_SIZE 16
#define CTR_MODE_LEN_SHIFT 4
#define CTR_128BIT_COUNTER 16
#define AES_SM4_BLOCK_SIZE 16
#define LEFT_MOST_BIT 7

static inline uint32_t multiple_round(uint32_t x, uint32_t y)
{
	uint32_t res = 0;

	if (ADD_OVERFLOW(x, y - 1, &res))
		res = UINT32_MAX;

	return res / y;
}

struct sec_cipher_ctx {
	uint8_t key[SEC_MAX_CIPHER_KEY_SIZE];
	uint8_t iv[SEC_MAX_IV_SIZE];
	uint64_t key_dma;
	uint64_t iv_dma;
	uint8_t *in;
	uint64_t in_dma;
	uint8_t *out;
	uint64_t out_dma;
	struct hisi_qp *qp;
	size_t offs;
	uint32_t len;
	uint8_t alg;
	uint8_t mode;
	uint8_t iv_len;
	uint8_t key_len; /* cipher key len */
	uint8_t c_key_len; /* cipher key type */
	bool encrypt;
};

#endif
