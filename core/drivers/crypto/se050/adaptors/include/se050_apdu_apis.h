/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_APDU_APIS_H_
#define SE050_APDU_APIS_H_

#include <se050.h>

struct s050_scp_rotate_cmd;

sss_status_t se050_factory_reset(pSe05xSession_t ctx);

bool se050_key_exists(uint32_t k_id, pSe05xSession_t ctx);

struct se050_rsa_keypair {
	uint8_t *e;
	size_t e_len;
	uint8_t *d;
	size_t d_len;
	uint8_t *n;
	size_t n_len;

	uint8_t *p;
	size_t p_len;
	uint8_t *q;
	size_t q_len;
	uint8_t *qp;
	size_t qp_len;
	uint8_t *dp;
	size_t dp_len;
	uint8_t *dq;
	size_t dq_len;
};

struct se050_rsa_keypub {
	uint8_t *e;
	size_t e_len;
	uint8_t *n;
	size_t n_len;
};

sss_status_t se050_key_store_set_rsa_key_bin(sss_se05x_key_store_t *k_store,
					     sss_se05x_object_t *k_object,
					     struct se050_rsa_keypair *k_pair,
					     struct se050_rsa_keypub *k_pub,
					     size_t k_bit_len);

sss_status_t se050_get_free_memory(pSe05xSession_t ctx, uint16_t *t,
				   SE05x_MemoryType_t type);

sss_status_t se050_scp03_send_rotate_cmd(pSe05xSession_t ctx,
					 struct s050_scp_rotate_cmd *cmd);

#endif /* SE050_APDU_APIS_H_ */
