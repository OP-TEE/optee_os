/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
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

enum versal_aes_operation { ENCRYPT, DECRYPT };

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
	FEATURES = 0U,
	RSA_SIGN_VERIFY,
	RSA_PUBLIC_ENCRYPT,
	RSA_PRIVATE_DECRYPT,
	RSA_KAT,
	SHA3_UPDATE = 32U,
	SHA3_KAT,
	ELLIPTIC_GENERATE_PUBLIC_KEY = 64U,
	ELLIPTIC_GENERATE_SIGN,
	ELLIPTIC_VALIDATE_PUBLIC_KEY,
	ELLIPTIC_VERIFY_SIGN,
	ELLIPTIC_KAT,
	AES_INIT = 96U,
	AES_OP_INIT,
	AES_UPDATE_AAD,
	AES_ENCRYPT_UPDATE,
	AES_ENCRYPT_FINAL,
	AES_DECRYPT_UPDATE,
	AES_DECRYPT_FINAL,
	AES_KEY_ZERO,
	AES_WRITE_KEY,
	AES_LOCK_USER_KEY,
	AES_KEK_DECRYPT,
	AES_SET_DPA_CM,
	AES_DECRYPT_KAT,
	AES_DECRYPT_CM_KAT,
	MAX,
};

#define MAX_IPI_REGS 6

struct cmd_args {
	uint32_t data[MAX_IPI_REGS];
	size_t dlen;
	struct ipi_buf ibuf[MAX_IPI_BUF];
};

TEE_Result versal_crypto_request(enum versal_crypto_api id,
				 struct cmd_args *arg, uint32_t *err);
#endif

