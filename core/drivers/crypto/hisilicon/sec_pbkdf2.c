// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, HiSilicon Technologies Co., Ltd.
 * Kunpeng hardware accelerator pbkdf2 implementation.
 */

#include <tee/tee_cryp_pbkdf2.h>
#include <tee/tee_cryp_utl.h>

#include "sec_main.h"
#include "sec_pbkdf2.h"

static enum hisi_drv_status sec_pbkdf2_parse_sqe(void *bd, void *msg __unused)
{
	struct hisi_sec_sqe *sqe = bd;
	uint16_t done = 0;

	done = SEC_GET_FIELD(sqe->type2.done_flag, SEC_DONE_MASK, 0);
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		EMSG("SEC do pbkdf2 fail! done=%#"PRIx16", etype=%#"PRIx8,
		     done, sqe->type2.error_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_pbkdf2_fill_sqe(void *bd, void *msg)
{
	struct sec_pbkdf2_msg *pbkdf2_msg = msg;
	struct hisi_sec_sqe *sqe = bd;

	sqe->type_auth_cipher = BD_TYPE2;
	sqe->type_auth_cipher |= SHIFT_U32(AUTH_MAC_CALCULATE, SEC_AUTH_OFFSET);
	sqe->sds_sa_type = SHIFT_U32(SCENE_PBKDF2, SEC_SCENE_OFFSET);

	sqe->type2.mac_key_alg = SHIFT_U32(pbkdf2_msg->derive_type,
					   SEC_AEAD_ALG_OFFSET);
	/* mac_len = 1 and a_key_len = 1 only for hardware check */
	sqe->type2.mac_key_alg |= 0x1;
	sqe->type2.mac_key_alg |= SHIFT_U32(0x1, SEC_AKEY_OFFSET);

	sqe->type2.alen_ivllen = pbkdf2_msg->salt_len;
	sqe->type2.clen_ivhlen = pbkdf2_msg->c_num;
	sqe->type2.pass_word_len = (uint16_t)pbkdf2_msg->key_len;
	sqe->type2.dk_len = (uint16_t)pbkdf2_msg->out_len;

	if (IS_ENABLED(CFG_CRYPTO_HW_PBKDF2_WITH_EFUSE))
		sqe->huk_ci_key = SHIFT_U32(SEC_HUK_ENABLE, SEC_HUK_OFFSET);
	else
		sqe->type2.a_key_addr = pbkdf2_msg->key_dma;

	sqe->type2.data_src_addr = pbkdf2_msg->salt_dma;
	sqe->type2.mac_addr = pbkdf2_msg->out_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_pbkdf2_parse_bd3_sqe(void *bd,
						     void *msg __unused)
{
	struct hisi_sec_bd3_sqe *sqe = bd;
	uint16_t done = 0;

	done = SEC_GET_FIELD(sqe->done_flag, SEC_DONE_MASK, 0);
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		EMSG("SEC do pbkdf2 fail! done=%#"PRIx16", etype=%#"PRIx8,
		     done, sqe->error_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_pbkdf2_fill_bd3_sqe(void *bd, void *msg)
{
	struct sec_pbkdf2_msg *pbkdf2_msg = msg;
	struct hisi_sec_bd3_sqe *sqe = bd;

	sqe->bd_param = BD_TYPE3 | SHIFT_U32(SCENE_PBKDF2, SEC_SCENE_OFFSET_V3);
	sqe->auth_mac_key = AUTH_MAC_CALCULATE;
	sqe->auth_mac_key |= SHIFT_U32(pbkdf2_msg->derive_type,
				       SEC_AUTH_ALG_OFFSET_V3);
	/* mac_len = 1 and a_key_len = 1 only for hardware check */
	sqe->auth_mac_key |= SHIFT_U32(0x1, SEC_AKEY_OFFSET_V3);
	sqe->auth_mac_key |= SHIFT_U32(0x1, SEC_MAC_OFFSET_V3);
	sqe->a_len_key = pbkdf2_msg->salt_len;
	sqe->pbkdf2_scene.pbkdf2_salt_len = pbkdf2_msg->salt_len;
	sqe->pbkdf2_scene.pass_word_dk_len = pbkdf2_msg->key_len;
	sqe->pbkdf2_scene.c_num = pbkdf2_msg->c_num;
	sqe->pbkdf2_scene.pass_word_dk_len |= SHIFT_U32(pbkdf2_msg->out_len,
						SEC_DK_LEN_OFFSET_V3);

	if (IS_ENABLED(CFG_CRYPTO_HW_PBKDF2_WITH_EFUSE))
		sqe->auth_mac_key |= SHIFT_U32(SEC_IMG_ROTKEY_AP,
					       SEC_KEY_SEL_OFFSET_V3);
	else
		sqe->a_key_addr = pbkdf2_msg->key_dma;

	sqe->data_src_addr = pbkdf2_msg->salt_dma;
	sqe->mac_addr = pbkdf2_msg->out_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result sec_pbkdf2_do_task(void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	TEE_Result res = TEE_SUCCESS;
	struct hisi_qp *qp = NULL;

	qp = sec_create_qp(HISI_QM_CHANNEL_TYPE1);
	if (!qp) {
		EMSG("Fail to create pbkdf2 qp");
		return TEE_ERROR_BUSY;
	}

	if (qp->qm->version == HISI_QM_HW_V2) {
		qp->fill_sqe = sec_pbkdf2_fill_sqe;
		qp->parse_sqe = sec_pbkdf2_parse_sqe;
	} else {
		qp->fill_sqe = sec_pbkdf2_fill_bd3_sqe;
		qp->parse_sqe = sec_pbkdf2_parse_bd3_sqe;
	}

	ret = hisi_qp_send(qp, msg);
	if (ret) {
		EMSG("Fail to send task, ret=%d", ret);
		res = TEE_ERROR_BAD_STATE;
		goto done_proc;
	}

	ret = hisi_qp_recv_sync(qp, msg);
	if (ret) {
		EMSG("Recv task error, ret=%d", ret);
		res = TEE_ERROR_BAD_STATE;
		goto done_proc;
	}

done_proc:
	hisi_qm_release_qp(qp);

	return res;
}

static TEE_Result sec_pbkdf2_dk_iteration_check(uint32_t alg, uint32_t c_num,
						size_t dk_len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t hash_len = 0;
	size_t t_num = 0;
	size_t time = 0;

	if (dk_len > SEC_MAX_DK_LEN) {
		EMSG("Unsupported derived key len %zu", dk_len);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (c_num > SEC_MAX_ITERATION_NUM) {
		EMSG("Unsupported iteration count %"PRIu32, c_num);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (c_num <= SEC_CRITICAL_ITERATION_NUM)
		return TEE_SUCCESS;

	ret = tee_alg_get_digest_size(alg, &hash_len);
	if (ret || hash_len == 0) {
		EMSG("Fail to get digest size");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	t_num = ROUNDUP_DIV(dk_len, hash_len);

	if (alg < TEE_ALG_HMAC_SHA384 || alg > TEE_ALG_HMAC_SHA512)
		time = t_num * SEC_PER_BLOCK_TIME1_NS * c_num;
	else
		time = t_num * SEC_PER_BLOCK_TIME2_NS * c_num;

	if (time > SEC_MAX_TIMEOUT_NS) {
		EMSG("Time %zu is more than sec max timeout", time);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_pbkdf2_params_check(uint32_t hash_id, size_t password_len,
					  size_t salt_len, uint32_t c_num,
					  size_t derived_key_len)
{
	uint32_t alg = TEE_ALG_HMAC_ALGO(hash_id);

	if (!password_len || !salt_len || !c_num || !derived_key_len) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((alg < TEE_ALG_HMAC_SHA384 || alg > TEE_ALG_HMAC_SHA512) &&
	    (password_len > (SEC_MAX_PASSWORD_LEN / 2))) {
		EMSG("Password_len %zu does not match alg %#"PRIx32,
		     password_len, alg);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (password_len > SEC_MAX_PASSWORD_LEN) {
		EMSG("Unsupported password len %zu", password_len);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (salt_len > SEC_MAX_SALT_LEN) {
		EMSG("Unsupported salt len %zu", salt_len);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return sec_pbkdf2_dk_iteration_check(alg, c_num, derived_key_len);
}

static TEE_Result sec_pbkdf2_set_derive_type(uint32_t hash_id,
					     struct sec_pbkdf2_msg *msg)
{
	uint32_t alg = TEE_ALG_HMAC_ALGO(hash_id);

	switch (alg) {
	case TEE_ALG_HMAC_SHA1:
		msg->derive_type = SEC_HMAC_SHA1;
		break;
	case TEE_ALG_HMAC_SHA224:
		msg->derive_type = SEC_HMAC_SHA224;
		break;
	case TEE_ALG_HMAC_SHA256:
		msg->derive_type = SEC_HMAC_SHA256;
		break;
	case TEE_ALG_HMAC_SHA384:
		msg->derive_type = SEC_HMAC_SHA384;
		break;
	case TEE_ALG_HMAC_SHA512:
		msg->derive_type = SEC_HMAC_SHA512;
		break;
	case TEE_ALG_HMAC_SM3:
		msg->derive_type = SEC_HMAC_SM3;
		break;
	default:
		EMSG("Invalid hamc alg type %#"PRIx32, alg);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_pbkdf2_set_buf(const uint8_t *password,
				     const uint8_t *salt,
				     struct sec_pbkdf2_msg *msg)
{
	msg->key_dma = virt_to_phys(msg->base_key);
	if (!msg->key_dma) {
		EMSG("Fail to get key dma addr");
		return TEE_ERROR_BAD_STATE;
	}

	msg->salt_dma = virt_to_phys(msg->salt);
	if (!msg->salt_dma) {
		EMSG("Fail to get salt dma addr");
		return TEE_ERROR_BAD_STATE;
	}

	msg->out_dma = virt_to_phys(msg->out);
	if (!msg->out_dma) {
		EMSG("Fail to get out dma addr");
		return TEE_ERROR_BAD_STATE;
	}

	if (password)
		memcpy(msg->base_key, password, msg->key_len);

	memcpy(msg->salt, salt, msg->salt_len);

	return TEE_SUCCESS;
}

static void sec_pbkdf2_clean_buf(struct sec_pbkdf2_msg *msg)
{
	memzero_explicit(msg->base_key, msg->key_len);
	memzero_explicit(msg->salt, msg->salt_len);
}

static TEE_Result sec_pbkdf2_msg_init(uint32_t hash_id, size_t password_len,
				      size_t salt_len, size_t derived_key_len,
				      uint32_t iteration_count,
				      struct sec_pbkdf2_msg *msg)
{
	msg->key_len = password_len;
	msg->salt_len = salt_len;
	msg->out_len = derived_key_len;
	msg->c_num = iteration_count;
	return sec_pbkdf2_set_derive_type(hash_id, msg);
}

TEE_Result tee_cryp_pbkdf2(uint32_t hash_id, const uint8_t *password,
			   size_t password_len, const uint8_t *salt,
			   size_t salt_len, uint32_t iteration_count,
			   uint8_t *derived_key, size_t derived_key_len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct sec_pbkdf2_msg *msg = NULL;

	if (!IS_ENABLED(CFG_CRYPTO_HW_PBKDF2_WITH_EFUSE) && !password) {
		EMSG("Password buf is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!salt || !derived_key) {
		EMSG("Invalid pbkdf2 buf");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = sec_pbkdf2_params_check(hash_id, password_len, salt_len,
				      iteration_count, derived_key_len);
	if (ret)
		return ret;

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		EMSG("Fail to calloc msg");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ret = sec_pbkdf2_msg_init(hash_id, password_len, salt_len,
				  derived_key_len, iteration_count, msg);
	if (ret)
		goto free_msg;

	ret = sec_pbkdf2_set_buf(password, salt, msg);
	if (ret)
		goto free_msg;

	ret = sec_pbkdf2_do_task(msg);
	if (ret)
		goto clean_buf;

	memcpy(derived_key, msg->out, msg->out_len);

clean_buf:
	sec_pbkdf2_clean_buf(msg);
free_msg:
	free(msg);

	return ret;
}
