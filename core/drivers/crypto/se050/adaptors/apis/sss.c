// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <config.h>
#include <crypto/crypto.h>
#include <se050.h>
#include <se050_utils.h>
#include <string.h>

static const sss_policy_u asym_key = {
	.type = KPolicy_Asym_Key,
	.auth_obj_id = 0,
	.policy = {
		.asymmkey = {
			.can_Sign = 1,
			.can_Verify = 1,
			.can_Encrypt = 1,
			.can_Decrypt = 1,
			.can_KD = 1,
			.can_Wrap = 1,
			.can_Write = 1,
			.can_Gen = 1,
			.can_Import_Export = 1,
			.can_KA = 1,
			.can_Read = 1,
			.can_Attest = 1,
		}
	}
};

static const sss_policy_u common = {
	.type = KPolicy_Common,
	.auth_obj_id = 0,
	.policy = {
		.common = {
			.can_Delete = 1,
			.req_Sm = 1,
		},
	},
};

sss_policy_t se050_asym_policy = {
	.nPolicies = 2,
	.policies = { &asym_key, &common },
};

sss_status_t se050_rotate_scp03_keys(struct sss_se05x_ctx *ctx)
{
	struct s050_scp_rotate_cmd cmd = { };
	sss_status_t status = kStatus_SSS_Fail;
	struct se050_scp_key cur_keys = { };
	struct se050_scp_key new_keys = { };
	SE_Connect_Ctx_t *connect_ctx = NULL;
	sss_se05x_session_t *session = NULL;

	if (!ctx)
		return kStatus_SSS_Fail;

	if (IS_ENABLED(CFG_CORE_SE05X_SCP03_EARLY))
		return kStatus_SSS_Fail;

	if (crypto_rng_read(new_keys.dek, sizeof(new_keys.dek)))
		return kStatus_SSS_Fail;

	if (crypto_rng_read(new_keys.mac, sizeof(new_keys.mac)))
		return kStatus_SSS_Fail;

	if (crypto_rng_read(new_keys.enc, sizeof(new_keys.enc)))
		return kStatus_SSS_Fail;

	status = se050_scp03_put_keys(&new_keys, &cur_keys);
	if (status != kStatus_SSS_Success)
		return status;

	connect_ctx = &ctx->open_ctx;
	session = &ctx->session;

	status = se050_scp03_prepare_rotate_cmd(ctx, &cmd, &new_keys);
	if (status != kStatus_SSS_Success)
		goto restore;

	sss_se05x_refresh_session(se050_session, NULL);
	sss_se05x_session_close(session);

	connect_ctx->skip_select_applet = 1;
	status = sss_se05x_session_open(session, kType_SSS_SE_SE05x, 0,
					kSSS_ConnectionType_Encrypted,
					connect_ctx);
	if (status != kStatus_SSS_Success)
		goto restore;

	status = se050_scp03_send_rotate_cmd(&session->s_ctx, &cmd);
	if (status != kStatus_SSS_Success)
		goto restore;

	sss_host_session_close(&ctx->host_session);
	sss_se05x_session_close(se050_session);
	memset(ctx, 0, sizeof(*ctx));

	if (se050_core_early_init(&new_keys))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
restore:
	se050_scp03_put_keys(&cur_keys, NULL);
	return status;
}

sss_status_t se050_enable_scp03(sss_se05x_session_t *session)
{
	struct se050_scp_key keys = { };
	sss_status_t status = kStatus_SSS_Success;
	static bool enabled;

	if (enabled)
		return kStatus_SSS_Success;

	status = se050_scp03_get_keys(&keys);
	if (status != kStatus_SSS_Success)
		return status;

	sss_se05x_session_close(session);

	if (se050_core_early_init(&keys))
		return kStatus_SSS_Fail;

	enabled = true;

	return kStatus_SSS_Success;
}

sss_status_t se050_session_open(struct sss_se05x_ctx *ctx,
				struct se050_scp_key *current_keys)
{
	sss_status_t status = kStatus_SSS_Fail;
	SE_Connect_Ctx_t *connect_ctx = NULL;
	sss_se05x_session_t *session = NULL;

	if (!ctx)
		return kStatus_SSS_Fail;

	connect_ctx = &ctx->open_ctx;
	session = &ctx->session;
	connect_ctx->connType = kType_SE_Conn_Type_T1oI2C;
	connect_ctx->portName = NULL;

	if (!current_keys) {
		return sss_se05x_session_open(session, kType_SSS_SE_SE05x, 0,
					      kSSS_ConnectionType_Plain,
					      connect_ctx);
	}

	status = se050_configure_host(&ctx->host_session,
				      &ctx->host_ks,
				      &ctx->open_ctx,
				      &ctx->se05x_auth,
				      kSSS_AuthType_SCP03,
				      current_keys);
	if (status != kStatus_SSS_Success)
		return status;

	return sss_se05x_session_open(session, kType_SSS_SE_SE05x, 0,
				      kSSS_ConnectionType_Encrypted,
				      connect_ctx);
}

sss_status_t se050_key_store_and_object_init(struct sss_se05x_ctx *ctx)
{
	if (!ctx)
		return kStatus_SSS_Fail;

	return sss_se05x_key_store_context_init(&ctx->ks, &ctx->session);
}
