// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Huawei Technologies Co., Ltd
 */

#ifndef _SM2_PKE_H_

#include <crypto/crypto.h>
#include <stdint.h>
#include <tee_api_types.h>

TEE_Result sm2_mbedtls_pke_encrypt(struct ecc_public_key *key,
				   const uint8_t *src, size_t src_len,
				   uint8_t *dst, size_t *dst_len);

TEE_Result sm2_mbedtls_pke_decrypt(struct ecc_keypair *key, const uint8_t *src,
				   size_t src_len, uint8_t *dst,
				   size_t *dst_len);
#endif /* _SM2_PKE_H_ */
