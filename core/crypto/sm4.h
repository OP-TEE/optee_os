/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */
#ifndef CORE_CRYPTO_SM4_H
#define CORE_CRYPTO_SM4_H

#include <stddef.h>
#include <stdint.h>

#define SM4_ENCRYPT	1
#define SM4_DECRYPT	0

struct sm4_context {
	int mode;         /* SM4_ENCRYPT/SM4_DECRYPT */
	uint32_t sk[32];  /* SM4 subkeys */
};

void sm4_setkey_enc(struct sm4_context *ctx, const uint8_t key[16]);
void sm4_setkey_dec(struct sm4_context *ctx, const uint8_t key[16]);
void sm4_crypt_ecb(struct sm4_context *ctx, size_t length, const uint8_t *input,
		   uint8_t *output);
void sm4_crypt_cbc(struct sm4_context *ctx, size_t length, uint8_t iv[16],
		   const uint8_t *input, uint8_t *output);
void sm4_crypt_ctr(struct sm4_context *ctx, size_t length, uint8_t ctr[16],
		   const uint8_t *input, uint8_t *output);

#endif /* CORE_CRYPTO_SM4_H */
