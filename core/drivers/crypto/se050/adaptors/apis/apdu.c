// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <adaptors.h>
#include <fsl_sss_api.h>
#include <scp.h>
#include <se050_apdu_apis.h>
#include <string.h>

sss_status_t se050_factory_reset(pSe05xSession_t ctx)
{
	if (!ctx)
		return kStatus_SSS_Fail;

	if (Se05x_API_DeleteAll_Iterative(ctx) == SM_OK)
		return kStatus_SSS_Success;

	return kStatus_SSS_Fail;
}

bool se050_key_exists(uint32_t key_id, pSe05xSession_t ctx)
{
	SE05x_Result_t inuse = kSE05x_Result_FAILURE;
	smStatus_t status = SM_OK;

	if (!ctx)
		return false;

	status = Se05x_API_CheckObjectExists(ctx, key_id, &inuse);
	if (status != SM_OK)
		return false;

	if (inuse == kSE05x_Result_SUCCESS)
		return true;

	return false;
}

static sss_status_t set_rsa_public(Se05xSession_t *s_ctx,
				   Se05xPolicy_t *policy,
				   sss_se05x_object_t *k_object,
				   struct se050_rsa_keypub *keypub,
				   size_t key_bit_len)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	SE05x_RSAKeyFormat_t rsa_format = kSE05x_RSAKeyFormat_RAW;
	smStatus_t status = SM_OK;

	if (k_object->isPersistant)
		type = kSE05x_TransientType_Persistent;

	switch (k_object->cipherType) {
	case kSSS_CipherType_RSA:
		rsa_format = kSE05x_RSAKeyFormat_RAW;
		break;
	case kSSS_CipherType_RSA_CRT:
		rsa_format = kSE05x_RSAKeyFormat_CRT;
		break;
	default:
		return kStatus_SSS_Fail;
	}

	status = Se05x_API_WriteRSAKey(s_ctx, policy, k_object->keyId,
				       (U16)key_bit_len,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       keypub->e, keypub->e_len,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_Public,
				       rsa_format);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       keypub->n, keypub->n_len,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       rsa_format);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_rsa_private_rsa(Se05xSession_t *s_ctx,
					Se05xPolicy_t *policy,
					sss_se05x_object_t *k_object,
					struct se050_rsa_keypair *keypair,
					size_t key_bit_len)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	smStatus_t status = SM_OK;

	if (k_object->isPersistant)
		type = kSE05x_TransientType_Persistent;

	status = Se05x_API_WriteRSAKey(s_ctx, policy, k_object->keyId,
				       (U16)key_bit_len,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       keypair->d, keypair->d_len,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_Pair,
				       kSE05x_RSAKeyFormat_RAW);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       keypair->n, keypair->n_len,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_RAW);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_rsa_private_rsa_crt(Se05xSession_t *s_ctx,
					    Se05xPolicy_t *policy,
					    sss_se05x_object_t *k_object,
					    struct se050_rsa_keypair *keypair,
					    size_t key_bit_len)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	smStatus_t status = SM_OK;

	if (k_object->isPersistant)
		type = kSE05x_TransientType_Persistent;

	status = Se05x_API_WriteRSAKey(s_ctx, policy, k_object->keyId,
				       (U16)key_bit_len,
				       keypair->p,
				       keypair->p_len,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_Private,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       keypair->q,
				       keypair->q_len,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       keypair->dp,
				       keypair->dp_len,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       keypair->dq,
				       keypair->dq_len,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       keypair->qp,
				       keypair->qp_len,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_rsa_keypair_rsa(Se05xSession_t *s_ctx,
					Se05xPolicy_t *policy,
					sss_se05x_object_t *k_object,
					struct se050_rsa_keypair *keypair,
					size_t key_bit_len)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	smStatus_t status = SM_OK;

	if (k_object->isPersistant)
		type = kSE05x_TransientType_Persistent;

	status = Se05x_API_WriteRSAKey(s_ctx, policy, k_object->keyId,
				       (U16)key_bit_len,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       keypair->e, keypair->e_len,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_Pair,
				       kSE05x_RSAKeyFormat_RAW);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       keypair->d, keypair->d_len,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_RAW);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       keypair->n, keypair->n_len,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_RAW);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_rsa_keypair_rsa_crt(Se05xSession_t *s_ctx,
					    Se05xPolicy_t *policy,
					    sss_se05x_object_t *k_object,
					    struct se050_rsa_keypair *keypair,
					    size_t key_bit_len)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	smStatus_t status = SM_OK;

	if (k_object->isPersistant)
		type = kSE05x_TransientType_Persistent;

	status = Se05x_API_WriteRSAKey(s_ctx, policy, k_object->keyId,
				       (U16)key_bit_len,
				       keypair->p, keypair->p_len,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_Pair,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       keypair->q, keypair->q_len,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       keypair->dp, keypair->dp_len,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       keypair->dq, keypair->dq_len,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       keypair->qp, keypair->qp_len,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       keypair->e, keypair->e_len,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	status = Se05x_API_WriteRSAKey(s_ctx, NULL, k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       keypair->n, keypair->n_len,
				       (SE05x_INS_t)type,
				       kSE05x_KeyPart_NA,
				       kSE05x_RSAKeyFormat_CRT);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t se050_key_store_set_rsa_key_bin(sss_se05x_key_store_t *store,
					     sss_se05x_object_t *k_object,
					     struct se050_rsa_keypair *keypair,
					     struct se050_rsa_keypub *keypub,
					     size_t key_bit_len)
{
	Se05xPolicy_t policy = { };

	if (!store || !store->session || !k_object)
		return kStatus_SSS_Fail;

	if (se050_key_exists(k_object->keyId, &store->session->s_ctx))
		key_bit_len = 0;

	switch (k_object->objectType) {
	case kSSS_KeyPart_Public:
		return set_rsa_public(&store->session->s_ctx,
				      &policy, k_object,
				      keypub, key_bit_len);
	case kSSS_KeyPart_Private:
		if (k_object->cipherType == kSSS_CipherType_RSA)
			return set_rsa_private_rsa(&store->session->s_ctx,
						   &policy, k_object,
						   keypair, key_bit_len);

		if (k_object->cipherType == kSSS_CipherType_RSA_CRT)
			return set_rsa_private_rsa_crt(&store->session->s_ctx,
						       &policy, k_object,
						       keypair, key_bit_len);
		return kStatus_SSS_Fail;
	case kSSS_KeyPart_Pair:
		if (k_object->cipherType == kSSS_CipherType_RSA)
			return set_rsa_keypair_rsa(&store->session->s_ctx,
						   &policy, k_object,
						   keypair, key_bit_len);

		if (k_object->cipherType == kSSS_CipherType_RSA_CRT)
			return set_rsa_keypair_rsa_crt(&store->session->s_ctx,
						       &policy, k_object,
						       keypair, key_bit_len);
		return kStatus_SSS_Fail;
	default:
		return kStatus_SSS_Fail;
	}
}

sss_status_t  se050_get_free_memory(pSe05xSession_t ctx, uint16_t *p,
				    SE05x_MemoryType_t type)
{
	if (p && ctx && Se05x_API_GetFreeMemory(ctx, type, p) == SM_OK)
		return kStatus_SSS_Success;

	return kStatus_SSS_Fail;
}

sss_status_t se050_scp03_send_rotate_cmd(pSe05xSession_t ctx,
					 struct s050_scp_rotate_cmd *cmd)
{
	uint8_t rsp[64] = { 0 };
	size_t rsp_len = sizeof(rsp);
	tlvHeader_t hdr = {
		.hdr = {
			[0] = 0x80,
			[1] = 0xd8,
			[2] = 0,
			[3] = PUT_KEYS_KEY_IDENTIFIER,
		},
	};
	smStatus_t st = SM_NOT_OK;

	if (!ctx || !cmd)
		return kStatus_SSS_Fail;

	hdr.hdr[2] = cmd->cmd[0];
	st = DoAPDUTxRx_s_Case4(ctx, &hdr, cmd->cmd, cmd->cmd_len,
				rsp, &rsp_len);

	if ((rsp_len - 1 > sizeof(rsp)) || rsp_len < 2)
		return kStatus_SSS_Fail;

	st = (rsp[rsp_len - 2] << 8) + rsp[rsp_len - 1];
	if (st != SM_OK)
		return kStatus_SSS_Fail;

	if (!memcmp(rsp, cmd->kcv, cmd->kcv_len))
		return kStatus_SSS_Success;

	return kStatus_SSS_Fail;
}

static uint8_t *alloc_pubkey_buf(struct se050_ecc_keypub *keypub, size_t *len)
{
	size_t pubkey_len = 0;
	uint8_t *pubkey = NULL;
	uint8_t *buf = NULL;

	pubkey_len = keypub->x_len + keypub->y_len + 1;
	buf = malloc(pubkey_len);
	if (!buf)
		return NULL;

	*buf = 0x04;
	pubkey = buf + 1;
	memcpy(pubkey, keypub->x, keypub->x_len);
	memcpy(pubkey + keypub->x_len, keypub->y, keypub->y_len);
	*len = pubkey_len;

	return buf;
}

sss_status_t se050_ecc_gen_shared_secret(pSe05xSession_t ctx, uint32_t kid,
					 struct se050_ecc_keypub *keypub,
					 uint8_t *secret, size_t *len)
{
	smStatus_t status = SM_OK;
	uint8_t *buf = NULL;
	size_t pubkey_len = 0;

	if (!keypub || !secret || !len)
		return kStatus_SSS_Fail;

	buf = alloc_pubkey_buf(keypub, &pubkey_len);
	if (!buf)
		return kStatus_SSS_Fail;

	status = Se05x_API_ECGenSharedSecret(ctx, kid,
					     buf, pubkey_len, secret, len);
	free(buf);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_ecc_public(Se05xSession_t *s_ctx,
				   Se05xPolicy_t *policy,
				   sss_se05x_object_t *k_object,
				   SE05x_TransientType_t type,
				   struct se050_ecc_keypub *keypub)
{
	size_t pubkey_len = 0;
	smStatus_t status = SM_NOT_OK;
	uint8_t *buf = NULL;

	buf = alloc_pubkey_buf(keypub, &pubkey_len);
	if (!buf)
		return kStatus_SSS_Fail;

	k_object->curve_id = keypub->curve;
	status = Se05x_API_WriteECKey(s_ctx, policy, SE05x_MaxAttemps_UNLIMITED,
				      k_object->keyId,
				      keypub->curve,
				      NULL,
				      0,
				      buf,
				      pubkey_len,
				      (SE05x_INS_t)type,
				      kSE05x_KeyPart_Public);
	free(buf);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_ecc_private(Se05xSession_t *s_ctx,
				    Se05xPolicy_t *policy,
				    sss_se05x_object_t *k_object,
				    SE05x_TransientType_t type,
				    struct se050_ecc_keypair *keypair)
{
	smStatus_t status = SM_NOT_OK;

	k_object->curve_id = keypair->pub.curve;
	status = Se05x_API_WriteECKey(s_ctx, policy, SE05x_MaxAttemps_UNLIMITED,
				      k_object->keyId,
				      keypair->pub.curve,
				      keypair->d,
				      keypair->d_len,
				      NULL,
				      0,
				      (SE05x_INS_t)type,
				      kSE05x_KeyPart_Private);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

static sss_status_t set_ecc_pair(Se05xSession_t *s_ctx,
				 Se05xPolicy_t *policy,
				 sss_se05x_object_t *k_object,
				 SE05x_TransientType_t type,
				 struct se050_ecc_keypair *keypair)
{
	size_t pubkey_len = 0;
	smStatus_t status = SM_NOT_OK;
	uint8_t *buf = NULL;

	buf = alloc_pubkey_buf(&keypair->pub, &pubkey_len);
	if (!buf)
		return kStatus_SSS_Fail;

	k_object->curve_id = keypair->pub.curve;
	status = Se05x_API_WriteECKey(s_ctx, policy, SE05x_MaxAttemps_UNLIMITED,
				      k_object->keyId,
				      keypair->pub.curve,
				      keypair->d,
				      keypair->d_len,
				      buf,
				      pubkey_len,
				      (SE05x_INS_t)type,
				      kSE05x_KeyPart_Pair);
	free(buf);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

sss_status_t se050_key_store_set_ecc_key_bin(sss_se05x_key_store_t *store,
					     sss_se05x_object_t *k_object,
					     struct se050_ecc_keypair *keypair,
					     struct se050_ecc_keypub *keypub)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	Se05xPolicy_t policy = { };

	if (!store || !store->session || !k_object)
		return kStatus_SSS_Fail;

	if (k_object->isPersistant)
		type = kSE05x_TransientType_Persistent;

	switch (k_object->objectType) {
	case kSSS_KeyPart_Public:
		if (!keypub)
			return kStatus_SSS_Fail;

		return set_ecc_public(&store->session->s_ctx,
				      &policy, k_object, type, keypub);
	case kSSS_KeyPart_Private:
		if (!keypair)
			return kStatus_SSS_Fail;

		return set_ecc_private(&store->session->s_ctx,
				       &policy, k_object, type, keypair);
	case kSSS_KeyPart_Pair:
		if (!keypair)
			return kStatus_SSS_Fail;

		return set_ecc_pair(&store->session->s_ctx,
				    &policy, k_object, type, keypair);
	default:
		return  kStatus_SSS_Fail;
	}
}

sss_status_t se050_key_store_get_ecc_key_bin(sss_se05x_key_store_t *store,
					     sss_se05x_object_t *k_object,
					     uint8_t *key, size_t *key_len)
{
	smStatus_t status = SM_NOT_OK;
	uint8_t *buf = NULL;
	size_t buflen = 0;

	if (!store || !store->session || !k_object || !key || !key_len)
		return kStatus_SSS_Fail;

	switch (k_object->cipherType) {
	case kSSS_CipherType_EC_NIST_P:
	case kSSS_CipherType_EC_NIST_K:
	case kSSS_CipherType_EC_BRAINPOOL:
	case kSSS_CipherType_EC_BARRETO_NAEHRIG:
	case kSSS_CipherType_EC_MONTGOMERY:
	case kSSS_CipherType_EC_TWISTED_ED:
		add_ecc_header(key, key_len, &buf, &buflen, k_object->curve_id);
		status = Se05x_API_ReadObject(&store->session->s_ctx,
					      k_object->keyId, 0, 0,
					      buf, key_len);
		if (status != SM_OK)
			return kStatus_SSS_Fail;

		*key_len += buflen;
		buflen = *key_len;
		get_ecc_raw_data(key, *key_len, &buf, &buflen,
				 k_object->curve_id);

		/* return only the binary data */
		*key_len = buflen;
		memcpy(key, buf, buflen);
		return kStatus_SSS_Success;
	default:
		return kStatus_SSS_Fail;
	}
}
