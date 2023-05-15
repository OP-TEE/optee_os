/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */
/**
 * \file sm3.h
 * thanks to Xyssl
 * author:goldboar
 * email:goldboar@163.com
 * 2011-10-26
 */
#ifndef CORE_CRYPTO_SM3_H
#define CORE_CRYPTO_SM3_H

#include <stddef.h>
#include <stdint.h>

struct sm3_context {
	uint32_t total[2];   /* number of bytes processed */
	uint32_t state[8];   /* intermediate digest state */
	uint8_t buffer[64];  /* data block being processed */
	uint8_t ipad[64];    /* HMAC: inner padding */
	uint8_t opad[64];    /* HMAC: outer padding */
};

void sm3_init(struct sm3_context *ctx);
void sm3_update(struct sm3_context *ctx, const uint8_t *input, size_t ilen);
void sm3_final(struct sm3_context *ctx, uint8_t output[32]);
void sm3(const uint8_t *input, size_t ilen, uint8_t output[32]);

void sm3_hmac_init(struct sm3_context *ctx, const uint8_t *key, size_t keylen);
void sm3_hmac_update(struct sm3_context *ctx, const uint8_t *input,
		     size_t ilen);
void sm3_hmac_final(struct sm3_context *ctx, uint8_t output[32]);
void sm3_hmac(const uint8_t *key, size_t keylen, const uint8_t *input,
	      size_t ilen, uint8_t output[32]);

#endif /* CORE_CRYPTO_SM3_H */
