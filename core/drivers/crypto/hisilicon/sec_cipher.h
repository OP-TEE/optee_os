/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022-2024 HiSilicon Limited. */

#ifndef __SEC_CIPHER_H__
#define __SEC_CIPHER_H__

#include <stdbool.h>
#include <stdint.h>

#include "hisi_qm.h"

#define DES_KEY_SIZE			8
#define SEC_3DES_2KEY_SIZE		(2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define SEC_SM4_XTS_KEY_SIZE		32
#define SEC_SM4_ECB_KEY_SIZE		16
#define SEC_MAX_CIPHER_KEY_SIZE		64
#define MAX_CIPHER_LENGTH		16776704
#define MIN_CIPHER_LENGTH		16
#define XTS_KEYSIZE_128			32
#define XTS_KEYSIZE_256			64
#define DES_CBC_IV_SIZE			8
#define AES_SM4_IV_SIZE			16
#define SEC_MAX_IV_SIZE			2
#define CTR_MODE_LEN_SHIFT		4
#define CTR_128BIT_COUNTER		16
#define AES_SM4_BLOCK_SIZE		16
#define LEFT_MOST_BIT			7
#define CTR_SRC_ALIGN_MASK		0xf
#define CTR_SRC_BLOCK_SIZE		0x10

#define CKEY_LEN_128_BIT		0x1
#define CKEY_LEN_192_BIT		0x2
#define CKEY_LEN_256_BIT		0x3
#define CKEY_LEN_SM4			0x0
#define CKEY_LEN_DES			0x1
#define CKEY_LEN_3DES_3KEY		0x1
#define CKEY_LEN_3DES_2KEY		0x3

enum sec_c_alg {
	C_ALG_DES = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES = 0x2,
	C_ALG_SM4 = 0x3,
};

enum sec_c_mode {
	C_MODE_ECB = 0x0,
	C_MODE_CBC = 0x1,
	C_MODE_CFB = 0x2,
	C_MODE_OFB = 0x3,
	C_MODE_CTR = 0x4,
	C_MODE_CCM = 0x5,
	C_MODE_GCM = 0x6,
	C_MODE_XTS = 0x7,
	C_MODE_CTS = 0x9,
};

enum sec_cipher_dir {
	NO_CIPHER,
	CIPHER_ENCRYPT,
	CIPHER_DECRYPT,
	HARDWARE_COPY,
};

struct sec_cipher_ctx {
	uint8_t key[SEC_MAX_CIPHER_KEY_SIZE];
	uint64_t iv[SEC_MAX_IV_SIZE];
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
	uint8_t key_len;
	uint8_t c_key_len;
	bool encrypt;
};
#endif /* __SEC_CIPHER_H__ */
