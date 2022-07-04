/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2022
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef IPI_H
#define IPI_H

#include <drivers/versal_mbox.h>

struct versal_rsa_input_param {
	uint64_t key_addr;
	uint64_t data_addr;
	uint32_t key_len;
};

struct versal_rsa_sign_param {
	uint64_t sign_addr;
	uint64_t hash_addr;
	uint32_t hash_len;
};

struct versal_ecc_sign_param {
	uint64_t hash_addr;
	uint64_t priv_key_addr;
	uint64_t epriv_key_addr;
	uint32_t curve;
	uint32_t hash_len;
};

struct versal_ecc_verify_param {
	uint64_t hash_addr;
	uint64_t pub_key_addr;
	uint64_t signature_addr;
	uint32_t curve;
	uint32_t hash_len;
};

enum versal_aes_operation { VERSAL_AES_ENCRYPT, VERSAL_AES_DECRYPT };

struct versal_aes_init {
	uint64_t iv_addr;
	uint32_t operation;
	uint32_t key_src;
	uint32_t key_len;
};

struct versal_aes_input_param {
	uint64_t input_addr;
	uint32_t input_len;
	uint32_t is_last;
};

enum versal_crypto_api {
	VERSAL_FEATURES = 0U,
	VERSAL_RSA_SIGN_VERIFY,
	VERSAL_RSA_PUBLIC_ENCRYPT,
	VERSAL_RSA_PRIVATE_DECRYPT,
	VERSAL_RSA_KAT,
	VERSAL_SHA3_UPDATE = 32U,
	VERSAL_SHA3_KAT,
	VERSAL_ELLIPTIC_GENERATE_PUBLIC_KEY = 64U,
	VERSAL_ELLIPTIC_GENERATE_SIGN,
	VERSAL_ELLIPTIC_VALIDATE_PUBLIC_KEY,
	VERSAL_ELLIPTIC_VERIFY_SIGN,
	VERSAL_ELLIPTIC_KAT,
	VERSAL_AES_INIT = 96U,
	VERSAL_AES_OP_INIT,
	VERSAL_AES_UPDATE_AAD,
	VERSAL_AES_ENCRYPT_UPDATE,
	VERSAL_AES_ENCRYPT_FINAL,
	VERSAL_AES_DECRYPT_UPDATE,
	VERSAL_AES_DECRYPT_FINAL,
	VERSAL_AES_KEY_ZERO,
	VERSAL_AES_WRITE_KEY,
	VERSAL_AES_LOCK_USER_KEY,
	VERSAL_AES_KEK_DECRYPT,
	VERSAL_AES_SET_DPA_CM,
	VERSAL_AES_DECRYPT_KAT,
	VERSAL_AES_DECRYPT_CM_KAT,
	VERSAL_CRYPTO_API_MAX
};

#define VERSAL_MAX_IPI_REGS 6

struct versal_cmd_args {
	uint32_t data[VERSAL_MAX_IPI_REGS];
	size_t dlen;
	struct versal_ipi_buf ibuf[VERSAL_MAX_IPI_BUF];
};

TEE_Result versal_crypto_request(enum versal_crypto_api id,
				 struct versal_cmd_args *arg, uint32_t *err);
#endif

