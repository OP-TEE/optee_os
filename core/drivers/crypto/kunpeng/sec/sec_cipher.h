/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, HiSilicon Limited
 */
#ifndef __SEC_CIPHER_H__
#define __SEC_CIPHER_H__

#include <drvcrypt.h>
#include <drvcrypt_cipher.h>

enum C_ALG {
	C_ALG_DES = 0x0,
	C_ALG_3DES = 0x1,
	C_ALG_AES = 0x2,
	C_ALG_SM4 = 0x3,
};

enum C_MODE {
	C_MODE_ECB	= 0x0,
	C_MODE_CBC	= 0x1,
	C_MODE_CFB	= 0x2,
	C_MODE_OFB	= 0x3,
	C_MODE_CTR	= 0x4,
	C_MODE_CCM	= 0x5,
	C_MODE_GCM	= 0x6,
	C_MODE_XTS	= 0x7,
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
#define MULTIPLE_ROUND(x, y) (((x) + (y) - 1) / (y))

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

int32_t sec_cipher_bd_parse(void *bd, void *msg);
int32_t sec_cipher_bd3_parse(void *bd, void *msg);

TEE_Result sec_cipher_ctx_allocate(void **ctx, uint32_t algo);
void sec_cipher_ctx_free(void *ctx);
TEE_Result sec_cipher_initialize(struct drvcrypt_cipher_init *dinit);
TEE_Result sec_cipher_update(struct drvcrypt_cipher_update *dupdate);
void sec_cipher_final(void *ctx __unused);
void sec_cipher_copy_state(void *dst_ctx, void *src_ctx);

#endif
