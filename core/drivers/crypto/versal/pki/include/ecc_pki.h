/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#ifndef ECC_PKI_H
#define ECC_PKI_H

#include <crypto/crypto.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

TEE_Result pki_ecc_get_key_size(uint32_t curve, size_t *bytes, size_t *bits);
void pki_memcpy_swp(uint8_t *to, const uint8_t *from, size_t len);
void pki_crypto_bignum_bn2bin_eswap(uint32_t curve,
				    struct bignum *from, uint8_t *to);
void pki_crypto_bignum_bin2bn_eswap(const uint8_t *from, size_t sz,
				    struct bignum *to);
TEE_Result pki_ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
			       size_t msg_len, size_t *len, uint8_t *buf);

#endif
