/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_SSS_APIS_H_
#define SE050_SSS_APIS_H_

#include <fsl_sss_se05x_types.h>
#include <nxScp03_Types.h>

extern sss_policy_t se050_asym_policy;
struct se050_scp_key;

struct sss_se05x_ctx {
	SE_Connect_Ctx_t open_ctx;
	sss_se05x_session_t session;
	sss_se05x_key_store_t ks;

	struct se050_auth_ctx {
		NXSCP03_StaticCtx_t static_ctx;
		NXSCP03_DynCtx_t dynamic_ctx;
	} se05x_auth;

	sss_user_impl_session_t host_session;
	sss_key_store_t host_ks;

	struct se05x_se_info {
		uint8_t applet[3];
		uint8_t oefid[2];
	} se_info;
};

sss_status_t se050_key_store_and_object_init(struct sss_se05x_ctx *ctx);
sss_status_t se050_enable_scp03(sss_se05x_session_t *session);
sss_status_t se050_rotate_scp03_keys(struct sss_se05x_ctx *ctx);
sss_status_t se050_session_open(struct sss_se05x_ctx *ctx,
				struct se050_scp_key *key);
#endif /* SE050_SSS_APIS_H_ */
