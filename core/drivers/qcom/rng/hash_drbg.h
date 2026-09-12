/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef HASH_DRBG_H
#define HASH_DRBG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#define HASH_DRBG_SEED_LEN	111
#define HASH_DRBG_HASH_LEN	64
#define HASH_DRBG_MAX_GENERATE	BIT(16)

struct hash_drbg_state {
	uint8_t V[HASH_DRBG_SEED_LEN];
	uint8_t C[HASH_DRBG_SEED_LEN];
	uint64_t reseed_counter;
	bool instantiated;
	bool test_mode;
};

TEE_Result hash_drbg_get_random(void *buf, size_t len);

void hash_drbg_uninstantiate(void);

#ifdef CFG_QCOM_HASH_DRBG_KAT
TEE_Result hash_drbg_test_enable(void);

TEE_Result hash_drbg_test_instantiate(const uint8_t *entropy, size_t elen,
				      const uint8_t *nonce, size_t nlen);

TEE_Result hash_drbg_test_generate(const uint8_t *add, size_t alen,
				   uint8_t *out, size_t olen);

TEE_Result hash_drbg_test_reseed(const uint8_t *entropy, size_t elen,
				 const uint8_t *add, size_t alen);

TEE_Result hash_drbg_test_get_state(uint64_t *counter, uint8_t *V,
				    size_t vlen, uint8_t *C, size_t clen);
#endif /* CFG_QCOM_HASH_DRBG_KAT */

#endif /* HASH_DRBG_H */
