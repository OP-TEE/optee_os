/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */
#ifndef LIBSM_SM4_H
#define LIBSM_SM4_H

#include <stddef.h>
#include <stdint.h>

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

struct sm4_context {
	int mode;         /* encrypt/decrypt */
	uint32_t sk[32];  /* SM4 subkeys */
};

void sm4_setkey_enc(struct sm4_context *ctx, unsigned char key[16]);
void sm4_setkey_dec(struct sm4_context *ctx, unsigned char key[16]);
void sm4_crypt_ecb(struct sm4_context *ctx, size_t length, uint8_t *input,
		   uint8_t *output);
void sm4_crypt_cbc(struct sm4_context *ctx, int mode, size_t length,
		   uint8_t iv[16], uint8_t *input, uint8_t *output);

#endif /* LIBSM_SM4_H */
