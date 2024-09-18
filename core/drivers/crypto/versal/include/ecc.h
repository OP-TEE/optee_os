/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) ProvenRun SAS, 2023
 */

#ifndef ECC_H
#define ECC_H

#include <crypto/crypto.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_api_types.h>

TEE_Result versal_ecc_get_key_size(uint32_t curve, size_t *bytes, size_t *bits);
TEE_Result versal_ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
				  size_t msg_len, size_t *len, uint8_t *buf);

TEE_Result versal_ecc_hw_init(void);
TEE_Result versal_ecc_kat_test(void);

TEE_Result versal_ecc_gen_keypair(struct ecc_keypair *s);
#ifdef CFG_VERSAL_PKI_PWCT
TEE_Result versal_ecc_keypair_pwct(struct ecc_keypair *s);
#endif
TEE_Result versal_ecc_verify(uint32_t algo, struct ecc_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len);
TEE_Result versal_ecc_sign(uint32_t algo, struct ecc_keypair *key,
			   const uint8_t *msg, size_t msg_len,
			   uint8_t *sig, size_t *sig_len);
TEE_Result versal_ecc_sign_ephemeral(uint32_t algo, size_t bytes,
				     struct ecc_keypair *key,
				     struct ecc_keypair *ephemeral,
				     const uint8_t *msg, size_t msg_len,
				     uint8_t *sig, size_t *sig_len);

void versal_memcpy_swp(uint8_t *to, const uint8_t *from, size_t len);
void versal_crypto_bignum_bn2bin_eswap(uint32_t curve, struct bignum *from,
				       uint8_t *to);
void versal_crypto_bignum_bin2bn_eswap(const uint8_t *from, size_t sz,
				       struct bignum *to);

#endif
