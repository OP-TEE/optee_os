/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_APDU_APIS_H_
#define SE050_APDU_APIS_H_

#include <se050.h>

struct s050_scp_rotate_cmd;

sss_status_t se050_factory_reset(pSe05xSession_t ctx);

sss_status_t se050_cipher_update_nocache(sss_se05x_symmetric_t *ctx,
					 const uint8_t *src, size_t src_len,
					 uint8_t *dst, size_t *dst_len);

uint8_t se050_key_exists(uint32_t k_id, pSe05xSession_t ctx);

/*
 * Key Store operations
 */
struct rsa_keypair_bin {
	uint8_t *e;		/* Public exponent */
	size_t e_len;
	uint8_t *d;		/* Private exponent */
	size_t d_len;
	uint8_t *n;		/* Modulus */
	size_t n_len;

	/* Optional CRT parameters (all NULL if unused) */
	uint8_t *p;		/* N = pq */
	size_t p_len;
	uint8_t *q;
	size_t q_len;
	uint8_t *qp;		/* 1/q mod p */
	size_t qp_len;
	uint8_t *dp;		/* d mod (p-1) */
	size_t dp_len;
	uint8_t *dq;		/* d mod (q-1) */
	size_t dq_len;
};

struct rsa_public_key_bin {
	uint8_t *e;		/* Public exponent */
	size_t e_len;
	uint8_t *n;		/* Modulus */
	size_t n_len;
};

struct ecc_public_key_bin {
	uint8_t *x;		/* Public value x */
	size_t x_len;
	uint8_t *y;		/* Public value y */
	size_t y_len;
	uint32_t curve;		/* Curve type */
};

struct ecc_keypair_bin {
	uint8_t *d;		/* Private value */
	size_t d_len;
	uint8_t *x;		/* Public value x */
	size_t x_len;
	uint8_t *y;		/* Public value y */
	size_t y_len;
	uint32_t curve;		/* Curve type */
};

sss_status_t se050_key_store_set_rsa_key_bin(sss_se05x_key_store_t *k_store,
					     sss_se05x_object_t *k_object,
					     struct rsa_keypair_bin *k_pair,
					     struct rsa_public_key_bin *k_pub,
					     size_t k_bit_len);

sss_status_t se050_key_store_set_ecc_key_bin(sss_se05x_key_store_t *k_store,
					     sss_se05x_object_t *k_object,
					     struct ecc_keypair_bin *k_pair,
					     struct ecc_public_key_bin *k_pub);

sss_status_t se050_key_store_get_ecc_key_bin(sss_se05x_key_store_t *k_store,
					     sss_se05x_object_t *k_oject,
					     uint8_t *key,
					     size_t *k_len);

sss_status_t se050_ecc_gen_shared_secret(pSe05xSession_t ctx,
					 uint32_t id,
					 struct ecc_public_key_bin *key_pub,
					 uint8_t *secret, unsigned long *len);

sss_status_t se050_get_free_memory(pSe05xSession_t ctx, uint16_t *t,
				   SE05x_MemoryType_t type);

sss_status_t se050_scp03_send_rotate_cmd(pSe05xSession_t ctx,
					 struct s050_scp_rotate_cmd *cmd);

#endif /* SE050_APDU_APIS_H_ */
