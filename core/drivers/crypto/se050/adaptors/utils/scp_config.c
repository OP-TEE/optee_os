// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/huk_subkey.h>
#include <kernel/mutex.h>
#include <kernel/refcount.h>
#include <kernel/tee_common_otp.h>
#include <kernel/thread.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <se050.h>
#include <se050_utils.h>
#include <scp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

static enum se050_scp03_ksrc scp03_ksrc;
static bool scp03_enabled;

#define SE050A1_ID 0xA204
#define SE050A2_ID 0xA205
#define SE050B1_ID 0xA202
#define SE050B2_ID 0xA203
#define SE050C1_ID 0xA200
#define SE050C2_ID 0xA201
#define SE050DV_ID 0xA1F4
#define SE051A2_ID 0xA565
#define SE051C2_ID 0xA564

#define SE050A1 0
#define SE050A2 1
#define SE050B1 2
#define SE050B2 3
#define SE050C1 4
#define SE050C2 5
#define SE050DV 6
#define SE051A2 7
#define SE051C2 8

static const struct se050_scp_key se050_default_keys[] = {
	[SE050A1] = {
		.enc = { 0x34, 0xae, 0x09, 0x67, 0xe3, 0x29, 0xe9, 0x51,
			0x8e, 0x72, 0x65, 0xd5, 0xad, 0xcc, 0x01, 0xc2 },
		.mac = { 0x52, 0xb2, 0x53, 0xca, 0xdf, 0x47, 0x2b, 0xdb,
			0x3d, 0x0f, 0xb3, 0x8e, 0x09, 0x77, 0x00, 0x99 },
		.dek = { 0xac, 0xc9, 0x14, 0x31, 0xfe, 0x26, 0x81, 0x1b,
			0x5e, 0xcb, 0xc8, 0x45, 0x62, 0x0d, 0x83, 0x44 },
	},
	[SE050A2] = {
		.enc = { 0x46, 0xa9, 0xc4, 0x8c, 0x34, 0xef, 0xe3, 0x44,
			0xa5, 0x22, 0xe6, 0x67, 0x44, 0xf8, 0x99, 0x6a },
		.mac = { 0x12, 0x03, 0xff, 0x61, 0xdf, 0xbc, 0x9c, 0x86,
			0x19, 0x6a, 0x22, 0x74, 0xae, 0xf4, 0xed, 0x28 },
		.dek = { 0xf7, 0x56, 0x1c, 0x6f, 0x48, 0x33, 0x61, 0x19,
			0xee, 0x39, 0x43, 0x9a, 0xab, 0x34, 0x09, 0x8e },
	},
	[SE050B1] = {
		.enc = { 0xd4, 0x99, 0xbc, 0x90, 0xde, 0xa5, 0x42, 0xcf,
			0x78, 0xd2, 0x5e, 0x13, 0xd6, 0x4c, 0xbb, 0x1f },
		.mac = { 0x08, 0x15, 0x55, 0x96, 0x43, 0xfb, 0x79, 0xeb,
			0x85, 0x01, 0xa0, 0xdc, 0x83, 0x3d, 0x90, 0x1f },
		.dek = { 0xbe, 0x7d, 0xdf, 0xb4, 0x06, 0xe8, 0x1a, 0xe4,
			0xe9, 0x66, 0x5a, 0x9f, 0xed, 0x64, 0x26, 0x7c },
	},
	[SE050B2] = {
		.enc = { 0x5f, 0xa4, 0x3d, 0x82, 0x02, 0xd2, 0x5e, 0x9a,
			0x85, 0xb1, 0xfe, 0x7e, 0x2d, 0x26, 0x47, 0x8d },
		.mac = { 0x10, 0x5c, 0xea, 0x22, 0x19, 0xf5, 0x2b, 0xd1,
			0x67, 0xa0, 0x74, 0x63, 0xc6, 0x93, 0x79, 0xc3 },
		.dek = { 0xd7, 0x02, 0x81, 0x57, 0xf2, 0xad, 0x37, 0x2c,
			0x74, 0xbe, 0x96, 0x9b, 0xcc, 0x39, 0x06, 0x27 },
	},
	[SE050C1] = {
		.enc = { 0x85, 0x2b, 0x59, 0x62, 0xe9, 0xcc, 0xe5, 0xd0,
			0xbe, 0x74, 0x6b, 0x83, 0x3b, 0xcc, 0x62, 0x87 },
		.mac = { 0xdb, 0x0a, 0xa3, 0x19, 0xa4, 0x08, 0x69, 0x6c,
			0x8e, 0x10, 0x7a, 0xb4, 0xe3, 0xc2, 0x6b, 0x47 },
		.dek = { 0x4c, 0x2f, 0x75, 0xc6, 0xa2, 0x78, 0xa4, 0xae,
			0xe5, 0xc9, 0xaf, 0x7c, 0x50, 0xee, 0xa8, 0x0c },
	},
	[SE050C2] = {
		.enc = { 0xbd, 0x1d, 0xe2, 0x0a, 0x81, 0xea, 0xb2, 0xbf,
			0x3b, 0x70, 0x9a, 0x9d, 0x69, 0xa3, 0x12, 0x54 },
		.mac = { 0x9a, 0x76, 0x1b, 0x8d, 0xba, 0x6b, 0xed, 0xf2,
			0x27, 0x41, 0xe4, 0x5d, 0x8d, 0x42, 0x36, 0xf5 },
		.dek = { 0x9b, 0x99, 0x3b, 0x60, 0x0f, 0x1c, 0x64, 0xf5,
			0xad, 0xc0, 0x63, 0x19, 0x2a, 0x96, 0xc9, 0x47 },
	},
	[SE050DV] = {
		.enc = { 0x35, 0xc2, 0x56, 0x45, 0x89, 0x58, 0xa3, 0x4f,
			0x61, 0x36, 0x15, 0x5f, 0x82, 0x09, 0xd6, 0xcd },
		.mac = { 0xaf, 0x17, 0x7d, 0x5d, 0xbd, 0xf7, 0xc0, 0xd5,
			0xc1, 0x0a, 0x05, 0xb9, 0xf1, 0x60, 0x7f, 0x78 },
		.dek = { 0xa1, 0xbc, 0x84, 0x38, 0xbf, 0x77, 0x93, 0x5b,
			0x36, 0x1a, 0x44, 0x25, 0xfe, 0x79, 0xfa, 0x29 },
	},
	[SE051A2] = {
		.enc = { 0x84, 0x0a, 0x5d, 0x51, 0x79, 0x55, 0x11, 0xc9,
			0xce, 0xf0, 0xc9, 0x6f, 0xd2, 0xcb, 0xf0, 0x41 },
		.mac = { 0x64, 0x6b, 0xc2, 0xb8, 0xc3, 0xa4, 0xd9, 0xc1,
			0xfa, 0x8d, 0x71, 0x16, 0xbe, 0x04, 0xfd, 0xfe },
		.dek = { 0x03, 0xe6, 0x69, 0x9a, 0xca, 0x94, 0x26, 0xd9,
			0xc3, 0x89, 0x22, 0xf8, 0x91, 0x4c, 0xe5, 0xf7 },
	},
	[SE051C2] = {
		.enc = { 0x88, 0xdb, 0xcd, 0x65, 0x82, 0x0d, 0x2a, 0xa0,
			0x6f, 0xfa, 0xb9, 0x2a, 0xa8, 0xe7, 0x93, 0x64 },
		.mac = { 0xa8, 0x64, 0x4e, 0x2a, 0x04, 0xd9, 0xe9, 0xc8,
			0xc0, 0xea, 0x60, 0x86, 0x68, 0x29, 0x99, 0xe5 },
		.dek = { 0x8a, 0x38, 0x72, 0x38, 0x99, 0x88, 0x18, 0x44,
			0xe2, 0xc1, 0x51, 0x3d, 0xac, 0xd9, 0xf8, 0x0d },
	},
};

static sss_status_t get_id_from_ofid(uint32_t ofid, uint32_t *id)
{
	switch (ofid) {
	case SE050A1_ID:
		*id = SE050A1;
		break;
	case SE050A2_ID:
		*id = SE050A2;
		break;
	case SE050B1_ID:
		*id = SE050B1;
		break;
	case SE050B2_ID:
		*id = SE050B2;
		break;
	case SE050C1_ID:
		*id = SE050C1;
		break;
	case SE050C2_ID:
		*id = SE050C2;
		break;
	case SE050DV_ID:
		*id = SE050DV;
		break;
	case SE051A2_ID:
		*id = SE051A2;
		break;
	case SE051C2_ID:
		*id = SE051C2;
		break;
	default:
		return kStatus_SSS_Fail;
	}

	return kStatus_SSS_Success;
}

static sss_status_t encrypt_key_and_get_kcv(uint8_t *enc, uint8_t *kc,
					    uint8_t *key,
					    struct sss_se05x_ctx *ctx,
					    uint32_t id)
{
	static const uint8_t ones[] = { [0 ... AES_KEY_LEN_nBYTE - 1] = 1 };
	uint8_t enc_len = AES_KEY_LEN_nBYTE;
	uint8_t kc_len = AES_KEY_LEN_nBYTE;
	sss_status_t st = kStatus_SSS_Fail;
	sss_object_t *dek_object = NULL;
	sss_se05x_symmetric_t symm = { };
	sss_se05x_object_t ko = { };
	uint8_t dek[AES_KEY_LEN_nBYTE] = { 0 };
	size_t dek_len = sizeof(dek);
	size_t dek_bit_len = dek_len * 8;

	st = sss_se05x_key_object_init(&ko, &ctx->ks);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_key_object_allocate_handle(&ko, id,
						  kSSS_KeyPart_Default,
						  kSSS_CipherType_AES,
						  AES_KEY_LEN_nBYTE,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_key_store_set_key(&ctx->ks, &ko, key, AES_KEY_LEN_nBYTE,
					 AES_KEY_LEN_nBYTE * 8, NULL, 0);
	if (st != kStatus_SSS_Success)
		goto out;

	st = sss_se05x_symmetric_context_init(&symm, &ctx->session, &ko,
					      kAlgorithm_SSS_AES_ECB,
					      kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success)
		goto out;

	st = sss_se05x_cipher_one_go(&symm, NULL, 0, ones, kc, kc_len);
	if (st != kStatus_SSS_Success)
		goto out;

	dek_object = &ctx->open_ctx.auth.ctx.scp03.pStatic_ctx->Dek;
	if (se050_host_key_store_get_key(&ctx->host_ks, dek_object,
					 dek, &dek_len, &dek_bit_len))
		goto out;

	st = sss_se05x_key_store_set_key(&ctx->ks, &ko, dek, AES_KEY_LEN_nBYTE,
					 AES_KEY_LEN_nBYTE * 8, NULL, 0);
	if (st != kStatus_SSS_Success)
		goto out;

	st = sss_se05x_cipher_one_go(&symm, NULL, 0, key, enc, enc_len);
out:
	if (symm.keyObject)
		sss_se05x_symmetric_context_free(&symm);

	sss_se05x_key_object_free(&ko);

	Se05x_API_DeleteSecureObject(&ctx->session.s_ctx, id);

	return st;
}

static sss_status_t prepare_key_data(uint8_t *key, uint8_t *cmd,
				     struct sss_se05x_ctx *ctx, uint32_t id)
{
	uint8_t kc[AES_KEY_LEN_nBYTE] = { 0 };
	sss_status_t status = kStatus_SSS_Fail;

	cmd[0] = PUT_KEYS_KEY_TYPE_CODING_AES;
	cmd[1] = AES_KEY_LEN_nBYTE + 1;
	cmd[2] = AES_KEY_LEN_nBYTE;
	cmd[3 + AES_KEY_LEN_nBYTE] = CRYPTO_KEY_CHECK_LEN;

	status = encrypt_key_and_get_kcv(&cmd[3], kc, key, ctx, id);
	if (status != kStatus_SSS_Success)
		return status;

	memcpy(&cmd[3 + AES_KEY_LEN_nBYTE + 1], kc, CRYPTO_KEY_CHECK_LEN);

	return kStatus_SSS_Success;
}

sss_status_t se050_scp03_prepare_rotate_cmd(struct sss_se05x_ctx *ctx,
					    struct s050_scp_rotate_cmd *cmd,
					    struct se050_scp_key *keys)

{
	sss_status_t status = kStatus_SSS_Fail;
	size_t kcv_len = 0;
	size_t cmd_len = 0;
	uint8_t key_version = 0;
	uint8_t *key[] = {
		[0] = keys->enc,
		[1] = keys->mac,
		[2] = keys->dek,
	};
	uint32_t oid = 0;
	size_t i = 0;

	key_version = ctx->open_ctx.auth.ctx.scp03.pStatic_ctx->keyVerNo;
	cmd->cmd[cmd_len] = key_version;
	cmd_len += 1;

	cmd->kcv[kcv_len] = key_version;
	kcv_len += 1;

	for (i = 0; i < ARRAY_SIZE(key); i++) {
		status = se050_get_oid(&oid);
		if (status != kStatus_SSS_Success)
			return kStatus_SSS_Fail;

		status = prepare_key_data(key[i], &cmd->cmd[cmd_len], ctx, oid);
		if (status != kStatus_SSS_Success)
			return kStatus_SSS_Fail;

		memcpy(&cmd->kcv[kcv_len],
		       &cmd->cmd[cmd_len + 3 + AES_KEY_LEN_nBYTE + 1],
		       CRYPTO_KEY_CHECK_LEN);

		cmd_len += 3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN;
		kcv_len += CRYPTO_KEY_CHECK_LEN;
	}

	cmd->cmd_len = cmd_len;
	cmd->kcv_len = kcv_len;

	return kStatus_SSS_Success;
}

static sss_status_t get_ofid_key(struct se050_scp_key *keys)
{
	uint32_t oefid = SHIFT_U32(se050_ctx.se_info.oefid[0], 8) |
			 SHIFT_U32(se050_ctx.se_info.oefid[1], 0);
	sss_status_t status = kStatus_SSS_Success;
	uint32_t id = 0;

	status = get_id_from_ofid(oefid, &id);
	if (status != kStatus_SSS_Success)
		return status;

	memcpy(keys, &se050_default_keys[id], sizeof(*keys));
	return kStatus_SSS_Success;
}

static sss_status_t get_config_key(struct se050_scp_key *keys __maybe_unused)
{
#ifdef CFG_CORE_SE05X_SCP03_CURRENT_DEK
	struct se050_scp_key current_keys = {
		.dek = { CFG_CORE_SE05X_SCP03_CURRENT_DEK },
		.mac = { CFG_CORE_SE05X_SCP03_CURRENT_MAC },
		.enc = { CFG_CORE_SE05X_SCP03_CURRENT_ENC },
	};

	memcpy(keys, &current_keys, sizeof(*keys));
	return kStatus_SSS_Success;
#else
	return kStatus_SSS_Fail;
#endif
}

sss_status_t se050_scp03_subkey_derive(struct se050_scp_key *keys)
{
	struct {
		const char *name;
		uint8_t *data;
	} key[3] = {
		[0] = { .name = "dek", .data = keys->dek },
		[1] = { .name = "mac", .data = keys->mac },
		[2] = { .name = "enc", .data = keys->enc },
	};
	uint8_t msg[SE050_SCP03_KEY_SZ + 3] = { 0 };
	size_t i = 0;

	if (tee_otp_get_die_id(msg + 3, SE050_SCP03_KEY_SZ))
		return kStatus_SSS_Fail;

	for (i = 0; i < ARRAY_SIZE(key); i++) {
		memcpy(msg, key[i].name, 3);
		if (huk_subkey_derive(HUK_SUBKEY_SE050, msg, sizeof(msg),
				      key[i].data, SE050_SCP03_KEY_SZ))
			return kStatus_SSS_Fail;
	}

	return kStatus_SSS_Success;
}

bool se050_scp03_enabled(void)
{
	return scp03_enabled;
}

void se050_scp03_set_enable(enum se050_scp03_ksrc ksrc)
{
	scp03_enabled = true;
	scp03_ksrc = ksrc;
}

void se050_scp03_set_disable(void)
{
	scp03_enabled = false;
}

sss_status_t se050_scp03_get_keys(struct se050_scp_key *keys,
				  enum se050_scp03_ksrc ksrc)
{
	switch (ksrc) {
	case SCP03_CFG:
		return get_config_key(keys);
	case SCP03_DERIVED:
		return se050_scp03_subkey_derive(keys);
	case SCP03_OFID:
		return get_ofid_key(keys);
	default:
		return kStatus_SSS_Fail;
	}
}

sss_status_t se050_scp03_get_current_keys(struct se050_scp_key *keys)
{
	if (se050_scp03_enabled())
		return se050_scp03_get_keys(keys, scp03_ksrc);

	return kStatus_SSS_Fail;
}
