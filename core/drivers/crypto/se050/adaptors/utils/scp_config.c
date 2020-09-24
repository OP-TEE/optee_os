// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <kernel/refcount.h>
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
#include <tee/tadb.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_rpc.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_storage.h>
#include <utee_defines.h>

#define SE050A1_ID 0xA204
#define SE050A2_ID 0xA205
#define SE050B1_ID 0xA202
#define SE050B2_ID 0xA203
#define SE050C1_ID 0xA200
#define SE050C2_ID 0xA201
#define SE050DV_ID 0xA1F4

#define SE050A1 0
#define SE050A2 1
#define SE050B1 2
#define SE050B2 3
#define SE050C1 4
#define SE050C2 5
#define SE050DV 6

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
};

struct tee_scp03db_dir {
	const struct tee_file_operations *ops;
	struct tee_file_handle *fh;
};

static const char scp03db_obj_id[] = "scp03.db";
static struct tee_pobj po = {
	.obj_id_len = sizeof(scp03db_obj_id),
	.obj_id = (void *)scp03db_obj_id,
};

static TEE_Result __maybe_unused scp03db_delete_keys(void)
{
	struct tee_scp03db_dir *db = calloc(1, sizeof(struct tee_scp03db_dir));
	TEE_Result res = TEE_SUCCESS;

	if (!db)
		return TEE_ERROR_OUT_OF_MEMORY;

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	res = db->ops->open(&po, NULL, &db->fh);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		free(db);
		return TEE_SUCCESS;
	}

	if (res) {
		free(db);
		return res;
	}

	db->ops->close(&db->fh);
	db->ops->remove(&po);
	free(db);

	return TEE_SUCCESS;
}

static TEE_Result scp03db_write_keys(struct se050_scp_key *keys)
{
	struct tee_scp03db_dir *db = calloc(1, sizeof(struct tee_scp03db_dir));
	TEE_Result res = TEE_SUCCESS;
	size_t len = sizeof(*keys);

	if (!db)
		return TEE_ERROR_OUT_OF_MEMORY;

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	res = db->ops->open(&po, NULL, &db->fh);
	if (res && res != TEE_ERROR_ITEM_NOT_FOUND) {
		free(db);
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
	}

	res = db->ops->create(&po, true, NULL, 0, NULL, 0, keys, len, &db->fh);
	db->ops->close(&db->fh);
	free(db);

	return res;
}

static TEE_Result scp03db_read_keys(struct se050_scp_key *keys)
{
	struct tee_scp03db_dir *db = calloc(1, sizeof(struct tee_scp03db_dir));
	TEE_Result res = TEE_SUCCESS;
	size_t len = sizeof(*keys);

	if (!db)
		return TEE_ERROR_OUT_OF_MEMORY;

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	res = db->ops->open(&po, NULL, &db->fh);
	if (res) {
		free(db);
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
	}

	res = db->ops->read(db->fh, 0, keys, &len);
	if (res)
		goto close;

	if (len != sizeof(*keys))
		res = TEE_ERROR_GENERIC;
close:
	db->ops->close(&db->fh);
	free(db);

	return res;
}

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
		status = se050_get_oid(kKeyObject_Mode_Transient, &oid);
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
	sss_status_t status = kStatus_SSS_Success;
	uint32_t id = 0;

	status = get_id_from_ofid(CFG_CORE_SE05X_OEFID, &id);
	if (status != kStatus_SSS_Success)
		return status;

	memcpy(keys, &se050_default_keys[id], sizeof(*keys));
	return kStatus_SSS_Success;
}

static sss_status_t get_db_key(struct se050_scp_key *keys)
{
	if (IS_ENABLED(CFG_CORE_SE05X_SCP03_EARLY)) {
		/*
		 * File system access requires the REE or RPMB to be ready to
		 * respond to RPC calls (memory allocation and so forth).
		 * TODO.
		 */
		return kStatus_SSS_Fail;
	}

	if (scp03db_read_keys(keys))
		return kStatus_SSS_Fail;

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

sss_status_t se050_scp03_get_keys(struct se050_scp_key *keys)
{
	sss_status_t (*get_keys[])(struct se050_scp_key *) = {
		&get_config_key, &get_db_key, &get_ofid_key,
	};
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(get_keys); i++)
		if ((*get_keys[i])(keys) == kStatus_SSS_Success)
			return kStatus_SSS_Success;

	return kStatus_SSS_Fail;
}

sss_status_t se050_scp03_put_keys(struct se050_scp_key *keys,
				  struct se050_scp_key *cur_keys)

{
	sss_status_t status = kStatus_SSS_Success;

	if (cur_keys) {
		status = se050_scp03_get_keys(cur_keys);
		if (status != kStatus_SSS_Success)
			return status;
	}

	if (scp03db_write_keys(keys))
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}
