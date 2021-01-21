/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020-2021, Huawei Technologies Co., Ltd
 */

#ifndef CRYPTO_SM2_KDF_H
#define CRYPTO_SM2_KDF_H

#include <stdint.h>
#include <tee_api_types.h>

TEE_Result sm2_kdf(const uint8_t *Z, size_t Z_len, uint8_t *t, size_t tlen);
#endif /* CRYPTO_SM2_KDF_H */
