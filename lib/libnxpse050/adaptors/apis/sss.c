// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <se050.h>
#include <se050_utils.h>
#include <string.h>

extern TEE_Result se050_core_service_init(struct se050_scp_key *keys);

/*
 * policies
 */

/* currently only asymmetric keys are stored in the SE050 NVM */
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
	/* object can only be deleted by a secured and authenticated session */
	.policy = {
		.common = {
			.can_Delete = 1,
			.req_Sm = 1,
		},
	},
};

/* asym keys policy */
sss_policy_t se050_asym_policy = {
	.nPolicies = 2,
	.policies = { &asym_key, &common },
};

/*
 * @param ctx
 *
 * @return sss_status_t
 */
sss_status_t se050_rotate_scp03_keys(struct sss_se05x_ctx *ctx)
{
	struct s050_scp_rotate_cmd cmd = { 0 };
	sss_status_t status = kStatus_SSS_Fail;
	struct se050_scp_key cur_keys = { 0 };
	struct se050_scp_key new_keys = { 0 };
	SE_Connect_Ctx_t *connect_ctx = NULL;
	sss_se05x_session_t *session = NULL;

#if defined(CFG_CORE_SE05X_SCP03_EARLY)
	/* if SCP03 was enabled during early boot, we won't be able to read
	 * the keys from storage once they are rotated and written as the
	 * filesystem is not ready so early.
	 *
	 * Therefore disable scp03 key rotation.
	 */
	return kStatus_SSS_Fail;
#endif
	if (!ctx)
		return kStatus_SSS_Fail;

	if (crypto_rng_read(new_keys.dek, sizeof(new_keys.dek)) != TEE_SUCCESS)
		return kStatus_SSS_Fail;

	if (crypto_rng_read(new_keys.mac, sizeof(new_keys.mac)) != TEE_SUCCESS)
		return kStatus_SSS_Fail;

	if (crypto_rng_read(new_keys.enc, sizeof(new_keys.enc)) != TEE_SUCCESS)
		return kStatus_SSS_Fail;

	IMSG("write new scp03 keys to secure storage");
	status = se050_scp03_put_keys(&new_keys, &cur_keys);
	if (status != kStatus_SSS_Success) {
		EMSG("scp03 keys not updated");
		return status;
	}

	IMSG("scp03 keys updated in secure storage");

	connect_ctx = &ctx->open_ctx;
	session = &ctx->session;

	status = se050_scp03_prepare_rotate_cmd(ctx, &cmd, &new_keys);
	if (status != kStatus_SSS_Success) {
		EMSG("scp03.db keys corrupted, attempt restore");
		goto restore;
	}

	sss_se05x_refresh_session(se050_session, NULL);
	sss_se05x_session_close(session);

	/* unselect the applet so provision can proceed */
	connect_ctx->skip_select_applet = 1;
	status = sss_se05x_session_open(session, kType_SSS_SE_SE05x, 0,
					kSSS_ConnectionType_Encrypted,
					connect_ctx);
	if (status != kStatus_SSS_Success) {
		EMSG("scp03.db keys corrupted, attempt restore");
		goto restore;
	}

	IMSG("write scp03 keys to se050");
	status = se050_scp03_send_rotate_cmd(&session->s_ctx, &cmd);
	if (status != kStatus_SSS_Success) {
		EMSG("scp03.db keys corrupted, attempt restore");
		goto restore;
	}
	IMSG("write ok");

	sss_host_session_close(&ctx->host_session);
	sss_se05x_session_close(se050_session);
	memset(ctx, 0, sizeof(*ctx));

	if (se050_core_service_init(&new_keys) != TEE_SUCCESS) {
		EMSG("se050 down");
		panic();
	} else {
		IMSG("se050 ready [scp03 on]");
	}

	return status;
restore:
	if (se050_scp03_put_keys(&cur_keys, NULL) != kStatus_SSS_Success)
		EMSG("scp03.db keys corrupted!!");
	else
		IMSG("scp03.db restored");

	return status;
}

/*
 * @param ctx
 *
 * @return sss_status_t
 */
sss_status_t se050_enable_scp03(sss_se05x_session_t *session)
{
	struct se050_scp_key keys = { 0 };
	sss_status_t status = kStatus_SSS_Success;
	static bool enabled;

	if (enabled)
		return kStatus_SSS_Success;

	status = se050_scp03_get_keys(&keys);
	if (status != kStatus_SSS_Success)
		return status;

	sss_se05x_session_close(session);

	if (se050_core_service_init(&keys) != TEE_SUCCESS)
		return kStatus_SSS_Fail;

	enabled = true;

	IMSG("se050 ready [scp03 on]");
	return kStatus_SSS_Success;
}

/*
 * @param ctx
 * @param encryption
 *
 * @return sss_status_t
 */
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
	if (status != kStatus_SSS_Success) {
		EMSG("can't configure host");
		return status;
	}

	return sss_se05x_session_open(session, kType_SSS_SE_SE05x, 0,
				      kSSS_ConnectionType_Encrypted,
				      connect_ctx);
}

/*
 * @param ctx
 *
 * @return sss_status_t
 */
sss_status_t se050_key_store_and_object_init(struct sss_se05x_ctx *ctx)
{
	sss_status_t status = kStatus_SSS_Fail;

	if (!ctx)
		return status;

	status = sss_se05x_key_store_context_init(&ctx->ks, &ctx->session);
	if (status != kStatus_SSS_Success)
		EMSG(" sss_key_store_context_init Failed...");

	return status;
}

/*
 * pkcs-11 key deletion support:
 * scan a buffer looking for a persistent key and delete it from the SE050
 * memory
 */
void se050_delete_persistent_key(uint8_t *data, size_t len)
{
	sss_se05x_object_t k_object = { 0 };
	uint32_t val = SE050_KEY_WATERMARK;
	sss_status_t status;
	uint8_t *p = data;
	bool found = false;

	if (!p) {
		EMSG("invalid buffer");
		return;
	}

	/*
	 * persistent keys were watermarked so they could be found in the buffer
	 */
	while (len > sizeof(uint64_t) && !found) {
		if (memcmp(p, &val, sizeof(val)) != 0) {
			p++;
			len--;
			continue;
		}
		found = true;
	}

	if (!found)
		return;

	p = p - 4;
	memcpy((void *)&val, p, sizeof(val));

	status = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (status != kStatus_SSS_Success) {
		EMSG("error deleting persistent key");
		return;
	}

	status = sss_se05x_key_object_get_handle(&k_object, val);
	if (status != kStatus_SSS_Success) {
		EMSG("error deleting persistent key");
		return;
	}

	status = sss_se05x_key_store_erase_key(se050_kstore, &k_object);
	if (status != kStatus_SSS_Success) {
		EMSG("error deleting persistent key");
		return;
	}

	IMSG("deleted se050 persistent key 0x%x", val);
}
