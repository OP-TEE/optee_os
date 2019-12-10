/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */
/*
 *  mbedtlsSM2
 *
 *  Created by mac on 2018/4/18.
 *  Copyright 2018 mac. All rights reserved.
 */

#ifndef LIBSM_SM2_H
#define LIBSM_SM2_H

#include <mbedtls/ecp.h>

#define MAX_POINT_BYTE_LENGTH	64
#define HASH_BYTE_LENGTH	32

struct sm2_sign_ctx {
	uint8_t *message;
	size_t message_size;

	uint8_t *ID;
	size_t ENTL;

	mbedtls_ecp_keypair *key_pair;

	uint8_t Z[HASH_BYTE_LENGTH];
	uint8_t k[MAX_POINT_BYTE_LENGTH];
	uint8_t r[MAX_POINT_BYTE_LENGTH];
	uint8_t s[MAX_POINT_BYTE_LENGTH];
	uint8_t R[MAX_POINT_BYTE_LENGTH];
};

struct sm2_hash {
	uint8_t buffer[1024];
	int position;
	uint8_t hash[HASH_BYTE_LENGTH];
};

int sm2_sign(mbedtls_ecp_group *ecp, struct sm2_sign_ctx *ctx);
int sm2_verify(mbedtls_ecp_group *ecp, struct sm2_sign_ctx *ctx);

#endif /* LIBSM_SM2_H */
