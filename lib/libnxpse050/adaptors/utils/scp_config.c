// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 *
 * This sequence follows the Global Platform Specification 2.2 - Amendment D
 * for Secure Channel Protocol 03
 *
 */
#include <assert.h>
#include <bitstring.h>
#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <kernel/refcount.h>
#include <kernel/thread.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <se050.h>
#include <se050_default_keys.h>
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

struct tee_scp03db_dir {
	const struct tee_file_operations *ops;
	struct tee_file_handle *fh;
};

static const char scp03db_obj_id[] = "scp03.db";
static struct tee_pobj po = {
	.obj_id_len = sizeof(scp03db_obj_id),
	.obj_id = (void *)scp03db_obj_id,
};

static TEE_Result scp03db_delete_keys(void)__unused;
static TEE_Result scp03db_delete_keys(void)
{
	struct tee_scp03db_dir *db = calloc(1, sizeof(struct tee_scp03db_dir));
	TEE_Result res = TEE_SUCCESS;

	assert(db);

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	res = db->ops->open(&po, NULL, &db->fh);

	/* nothing to delete */
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		free(db);
		return TEE_SUCCESS;
	}

	/* the filesystem might not be accessibe */
	if (res != TEE_SUCCESS)
		panic();

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

	assert(db);

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	res = db->ops->open(&po, NULL, &db->fh);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND) {
		EMSG("scp03.db does not exist 0x%x", res);
		free(db);
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
	}

	IMSG("write scp03.db");
	res = db->ops->create(&po, true, NULL, 0, NULL, 0, keys, len, &db->fh);
	if (res != TEE_SUCCESS) {
		EMSG("scp03.db failed to write");
		goto close;
	}
	IMSG("write ok");

	IMSG("---------------------------------------------------");
	IMSG("WARNING: Leaking SCP03 KEYS - remove for production");
	IMSG("scp03 new keys");
	nLog_au8("scp03.db ", 0xff, "dek: ", keys->dek, sizeof(keys->dek));
	nLog_au8("scp03.db ", 0xff, "mac: ", keys->mac, sizeof(keys->mac));
	nLog_au8("scp03.db ", 0xff, "enc: ", keys->enc, sizeof(keys->enc));
	IMSG("---------------------------------------------------");
close:
	db->ops->close(&db->fh);
	free(db);

	return res;
}

static TEE_Result scp03db_read_keys(struct se050_scp_key *keys)
{
	struct tee_scp03db_dir *db = calloc(1, sizeof(struct tee_scp03db_dir));
	TEE_Result res = TEE_SUCCESS;
	size_t len = sizeof(*keys);

	assert(db);

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	res = db->ops->open(&po, NULL, &db->fh);
	if (res != TEE_SUCCESS) {
		EMSG("scp03.db does not exist 0x%x", res);
		free(db);
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
	}

	IMSG("read scp03.db");
	res = db->ops->read(db->fh, 0, keys, &len);
	if (res != TEE_SUCCESS) {
		EMSG("scp03.db failed to read");
		goto close;
	}

	if (len != sizeof(*keys)) {
		EMSG("scp03.db corrupted");
		res = TEE_ERROR_GENERIC;
	}

close:
	db->ops->close(&db->fh);
	free(db);

	return res;
}

static sss_status_t encrypt_key_and_get_kcv(uint8_t *enc, uint8_t *kc,
					    uint8_t *key,
					    struct sss_se05x_ctx *ctx,
					    uint32_t id)
{
	uint8_t ones[AES_KEY_LEN_nBYTE] = { [0 ... AES_KEY_LEN_nBYTE - 1] = 1 };
	uint8_t enc_len = AES_KEY_LEN_nBYTE;
	uint8_t kc_len = AES_KEY_LEN_nBYTE;
	sss_status_t st = kStatus_SSS_Fail;
	sss_object_t *dek_object = NULL;
	sss_se05x_symmetric_t symm = { 0 };
	sss_se05x_object_t ko = { 0 };
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
		return kStatus_SSS_Fail;

	st = sss_se05x_symmetric_context_init(&symm, &ctx->session, &ko,
					      kAlgorithm_SSS_AES_ECB,
					      kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_cipher_one_go(&symm, NULL, 0, ones, kc, kc_len);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	/* Encyrpt the sensitive data with the scp03 dek */
	dek_object = &ctx->open_ctx.auth.ctx.scp03.pStatic_ctx->Dek;
	st = se050_host_key_store_get_key(&ctx->host_ks, dek_object,
					  dek, &dek_len, &dek_bit_len);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_key_store_set_key(&ctx->ks, &ko, dek, AES_KEY_LEN_nBYTE,
					 AES_KEY_LEN_nBYTE * 8, NULL, 0);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_cipher_one_go(&symm, NULL, 0, key, enc, enc_len);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	if (symm.keyObject)
		sss_se05x_symmetric_context_free(&symm);

	sss_se05x_key_object_free(&ko);

	/* SE050: BUG: these transient objects must be deleted */
	Se05x_API_DeleteSecureObject(&ctx->session.s_ctx, id);

	return kStatus_SSS_Success;
}

static sss_status_t prepare_key_data(uint8_t *key, uint8_t *cmd,
				     struct sss_se05x_ctx *ctx, uint32_t id)
{
	uint8_t kc[AES_KEY_LEN_nBYTE] = { 0 };
	sss_status_t status = kStatus_SSS_Fail;

	/* GP key type AES */
	cmd[0] = PUT_KEYS_KEY_TYPE_CODING_AES;
	/* Length of the 'AES key data' */
	cmd[1] = AES_KEY_LEN_nBYTE + 1;
	/* Length of 'AES key' */
	cmd[2] = AES_KEY_LEN_nBYTE;
	/* Length of key check  */
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
	/* order of elements in the array matters */
	uint8_t *key[] = { [0] = keys->enc,
			   [1] = keys->mac,
			   [2] = keys->dek,
	};
	uint32_t oid = 0;
	size_t i = 0;

	/* add version to replace in the header */
	key_version = ctx->open_ctx.auth.ctx.scp03.pStatic_ctx->keyVerNo;

	/* packet for SCP03 keys provision: key_version to replace */
	cmd->cmd[cmd_len] = key_version;
	cmd_len += 1;

	cmd->kcv[kcv_len] = key_version;
	kcv_len += 1;

	for (i = 0; i < ARRAY_SIZE(key); i++) {
		status = se050_get_oid(kKeyObject_Mode_Transient, &oid);
		if (status != kStatus_SSS_Success)
			goto error;

		status = prepare_key_data(key[i], &cmd->cmd[cmd_len], ctx, oid);
		if (status != kStatus_SSS_Success)
			goto error;

		memcpy(&cmd->kcv[kcv_len],
		       &cmd->cmd[cmd_len + 3 + AES_KEY_LEN_nBYTE + 1],
		       CRYPTO_KEY_CHECK_LEN);

		cmd_len += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
		kcv_len += CRYPTO_KEY_CHECK_LEN;
	}

	cmd->cmd_len = cmd_len;
	cmd->kcv_len = kcv_len;

	return kStatus_SSS_Success;
error:
	EMSG("error preparing scp03 rotation command");

	return kStatus_SSS_Fail;
}

/*
 * @param keys
 *
 * @return sss_status_t
 */
static sss_status_t get_ofid_key(struct se050_scp_key *keys)
{
#ifdef CFG_CORE_SE05X_OEFID
	sss_status_t status = kStatus_SSS_Success;
	uint32_t id = 0;

	status = se050_get_id_from_ofid(CFG_CORE_SE05X_OEFID, &id);
	if (status != kStatus_SSS_Success)
		return status;

	IMSG("scp03 current keys defaulting to OEFID");
	memcpy(keys, &se050_default_keys[id], sizeof(*keys));
	return kStatus_SSS_Success;
#else
	return kStatus_SSS_Fail;
#endif
}

static sss_status_t get_db_key(struct se050_scp_key *keys)
{
#if defined(CFG_CORE_SE05X_SCP03_EARLY)
	/* file system access requires the REE to be ready to respond to
	 * RPC calls (memory allocation and so forth). When the REE is not
	 * ready, the system locks up waiting for RPC.
	 */
	return kStatus_SSS_Fail;
#endif
	if (scp03db_read_keys(keys) == TEE_SUCCESS)
		return kStatus_SSS_Success;

	return kStatus_SSS_Fail;
}

static sss_status_t get_config_key(struct se050_scp_key *keys __unused)
{
#ifdef CFG_CORE_SE05X_SCP03_CURRENT_DEK
	struct se050_scp_key current_keys = {
		.dek = { CFG_CORE_SE05X_SCP03_CURRENT_DEK },
		.mac = { CFG_CORE_SE05X_SCP03_CURRENT_MAC },
		.enc = { CFG_CORE_SE05X_SCP03_CURRENT_ENC },
	};

	IMSG("scp03 current keys defaulting to CFG keys");
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
	panic();
}

/*
 * @param keys
 * @param cur_keys
 *
 * @return sss_status_t
 */
sss_status_t se050_scp03_put_keys(struct se050_scp_key *keys,
				  struct se050_scp_key *cur_keys)

{
	sss_status_t status = kStatus_SSS_Success;
	TEE_Result res = TEE_SUCCESS;

	if (!cur_keys)
		goto write;

	status = se050_scp03_get_keys(cur_keys);
	if (status != kStatus_SSS_Success) {
		EMSG("failed to get the current scp03 keys");
		return status;
	}

	IMSG("---------------------------------------------------");
	IMSG("WARNING: Leaking SCP03 KEYS - remove for production");
	IMSG("scp03: current keys");
	nLog_au8("scp03", 0xff, "dek: ", cur_keys->dek, sizeof(cur_keys->dek));
	nLog_au8("scp03", 0xff, "mac: ", cur_keys->mac, sizeof(cur_keys->mac));
	nLog_au8("scp03", 0xff, "enc: ", cur_keys->enc, sizeof(cur_keys->enc));
	IMSG("---------------------------------------------------");
write:
	res = scp03db_write_keys(keys);
	if (res != TEE_SUCCESS)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}
