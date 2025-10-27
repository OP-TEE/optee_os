/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#ifndef ECC_H
#define ECC_H

#include <crypto/crypto.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_api_types.h>

TEE_Result versal_ecc_verify(uint32_t algo, struct ecc_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len);
TEE_Result versal_ecc_sign(uint32_t algo, struct ecc_keypair *key,
			   const uint8_t *msg, size_t msg_len,
			   uint8_t *sig, size_t *sig_len);

TEE_Result versal_ecc_gen_keypair(struct ecc_keypair *s);

TEE_Result versal_ecc_hw_init(void);
TEE_Result versal_ecc_kat_test(void);

#endif
