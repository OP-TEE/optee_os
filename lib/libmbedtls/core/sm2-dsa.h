
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Huawei Technologies Co., Ltd
 */

#ifndef _SM2_DSA_H_

#include <crypto/crypto.h>
#include <stdint.h>
#include <tee_api_types.h>

TEE_Result sm2_mbedtls_dsa_sign(uint32_t algo, struct ecc_keypair *key,
				const uint8_t *msg, size_t msg_len,
				uint8_t *sig, size_t *sig_len);

TEE_Result sm2_mbedtls_dsa_verify(uint32_t algo, struct ecc_public_key *key,
				  const uint8_t *msg, size_t msg_len,
				  const uint8_t *sig, size_t sig_len);
#endif /* _SM2_DSA_H_ */
