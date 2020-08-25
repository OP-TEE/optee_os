// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <fsl_sss_api.h>
#include <scp.h>
#include <se050_apdu_apis.h>
#include <string.h>

/*
 * @param pCtx
 *
 * @return sss_status_t
 */
sss_status_t se050_factory_reset(pSe05xSession_t ctx)
{
	smStatus_t st = SM_OK;

	if (!ctx)
		return kStatus_SSS_Fail;

	st = Se05x_API_DeleteAll_Iterative(ctx);
	if (st != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

/*
 * @param context
 * @param src
 * @param src_len
 * @param dst
 * @param dst_len
 *
 * @return sss_status_t
 */
sss_status_t se050_cipher_update_nocache(sss_se05x_symmetric_t *ctx,
					 const uint8_t *src, size_t src_len,
					 uint8_t *dst, size_t *dst_len)
{
	smStatus_t status = SM_NOT_OK;

	if (!ctx || !src || !dst || !dst_len)
		return kStatus_SSS_Fail;

	status = Se05x_API_CipherUpdate(&ctx->session->s_ctx,
					ctx->cryptoObjectId,
					src, src_len,
					dst, dst_len);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

/*
 * @param key_id
 * @param session_ctx
 *
 * @return uint8_t
 */
uint8_t se050_key_exists(uint32_t key_id, pSe05xSession_t ctx)
{
	SE05x_Result_t inuse = kSE05x_Result_FAILURE;
	smStatus_t status = SM_OK;

	if (!ctx)
		return 0;

	status = Se05x_API_CheckObjectExists(ctx, key_id, &inuse);
	if (status != SM_OK)
		return 0;

	if (inuse == kSE05x_Result_SUCCESS)
		return 1;

	return 0;
}

/*
 * @param store
 * @param k_object
 * @param key_pair
 * @param key_pub
 * @param key_bit_len
 *
 * @return sss_status_t
 */
sss_status_t se050_key_store_set_rsa_key_bin(sss_se05x_key_store_t *store,
					     sss_se05x_object_t *k_object,
					     struct rsa_keypair_bin *key_pair,
					     struct rsa_public_key_bin *key_pub,
					     size_t key_bit_len)
{
	SE05x_RSAKeyFormat_t rsa_format = kSE05x_RSAKeyFormat_RAW;
	SE05x_TransientType_t type = kSE05x_TransientType_Transient;
	Se05xSession_t *s_ctx = NULL;
	uint32_t key_type = 0;
	Se05xPolicy_t policy = {
		.value = NULL, .value_len = 0,
	};
	sss_status_t ret = kStatus_SSS_Fail;
	smStatus_t status = SM_NOT_OK;

	if (!store || !store->session || !k_object)
		return kStatus_SSS_Fail;

	s_ctx = &store->session->s_ctx;
	key_type = k_object->objectType;
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
		ret = kStatus_SSS_Fail;
		goto exit;
	}

	if (se050_key_exists(k_object->keyId, s_ctx))
		key_bit_len = 0;

	if (key_type != kSSS_KeyPart_Public)
		goto label_private;

	/* Set the Public Exponent */
	status = Se05x_API_WriteRSAKey(s_ctx,
				       &policy,
				       k_object->keyId,
				       (U16)key_bit_len,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       key_pub->e,
				       key_pub->e_len,
				       SE05X_RSA_NO_priv,
				       SE05X_RSA_NO_pubMod,
				       type,
				       kSE05x_KeyPart_Public,
				       rsa_format);
	if (status != SM_OK) {
		EMSG("keybitlen %ld, e_len %ld", key_bit_len, key_pub->e_len);
		ret = kStatus_SSS_Fail;
		goto exit;
	}

	/* Set the Modulus */
	status = Se05x_API_WriteRSAKey(s_ctx,
				       NULL,
				       k_object->keyId,
				       0,
				       SE05X_RSA_NO_p,
				       SE05X_RSA_NO_q,
				       SE05X_RSA_NO_dp,
				       SE05X_RSA_NO_dq,
				       SE05X_RSA_NO_qInv,
				       SE05X_RSA_NO_pubExp,
				       SE05X_RSA_NO_priv,
				       key_pub->n,
				       key_pub->n_len,
				       type,
				       kSE05x_KeyPart_NA,
				       rsa_format);
	if (status == SM_OK)
		ret = kStatus_SSS_Success;

	goto exit;

label_private:
	if (key_type != kSSS_KeyPart_Private)
		goto label_pair;

	if (k_object->cipherType == kSSS_CipherType_RSA) {
		status = Se05x_API_WriteRSAKey(s_ctx,
					       &policy,
					       k_object->keyId,
					       (U16)key_bit_len,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       key_pair->d,
					       key_pair->d_len,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_Pair,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       key_pair->n,
					       key_pair->n_len,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status == SM_OK)
			ret = kStatus_SSS_Success;

		goto exit;
	}

	if (k_object->cipherType == kSSS_CipherType_RSA_CRT) {
		status = Se05x_API_WriteRSAKey(s_ctx,
					       &policy,
					       k_object->keyId,
					       (U16)key_bit_len,
					       key_pair->p,
					       key_pair->p_len,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_Private,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       key_pair->q,
					       key_pair->q_len,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       key_pair->dp,
					       key_pair->dp_len,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       key_pair->dq,
					       key_pair->dq_len,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       key_pair->qp,
					       key_pair->qp_len,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);

		if (status == SM_OK)
			ret = kStatus_SSS_Success;
	}

	goto exit;

label_pair:
	if (key_type != kSSS_KeyPart_Pair)
		goto exit;

	if (k_object->cipherType == kSSS_CipherType_RSA) {
		status = Se05x_API_WriteRSAKey(s_ctx,
					       &policy,
					       k_object->keyId,
					       (U16)key_bit_len,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       key_pair->e,
					       key_pair->e_len,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_Pair,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       key_pair->d,
					       key_pair->d_len,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       key_pair->n,
					       key_pair->n_len,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status == SM_OK)
			ret = kStatus_SSS_Success;

		goto exit;
	}

	if (k_object->cipherType == kSSS_CipherType_RSA_CRT) {
		status = Se05x_API_WriteRSAKey(s_ctx,
					       &policy,
					       k_object->keyId,
					       (U16)key_bit_len,
					       key_pair->p,
					       key_pair->p_len,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_Pair,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       key_pair->q,
					       key_pair->q_len,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       key_pair->dp,
					       key_pair->dp_len,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       key_pair->dq,
					       key_pair->dq_len,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       key_pair->qp,
					       key_pair->qp_len,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       key_pair->e,
					       key_pair->e_len,
					       SE05X_RSA_NO_priv,
					       SE05X_RSA_NO_pubMod,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);
		if (status != SM_OK) {
			ret = kStatus_SSS_Fail;
			goto exit;
		}

		status = Se05x_API_WriteRSAKey(s_ctx,
					       NULL,
					       k_object->keyId,
					       0,
					       SE05X_RSA_NO_p,
					       SE05X_RSA_NO_q,
					       SE05X_RSA_NO_dp,
					       SE05X_RSA_NO_dq,
					       SE05X_RSA_NO_qInv,
					       SE05X_RSA_NO_pubExp,
					       SE05X_RSA_NO_priv,
					       key_pair->n,
					       key_pair->n_len,
					       type,
					       kSE05x_KeyPart_NA,
					       rsa_format);

		if (status == SM_OK)
			ret = kStatus_SSS_Success;
	}
exit:
	return ret;
}

/*
 * @param store
 * @param k_object
 * @param key_pair
 * @param key_pub
 *
 * @return sss_status_t
 */
sss_status_t se050_key_store_set_ecc_key_bin(sss_se05x_key_store_t *store,
					     sss_se05x_object_t *k_object,
					     struct ecc_keypair_bin *key_pair,
					     struct ecc_public_key_bin *key_pub)
{
	SE05x_TransientType_t type = kSE05x_TransientType_Persistent;
	size_t public_keylen = 0;
	uint8_t buffer[256] = { 0x04 }; /* tag */
	uint8_t *public_key = buffer + 1;
	Se05xSession_t *s_ctx = NULL;
	Se05xPolicy_t policy = {
		.value = NULL, .value_len = 0,
	};
	sss_status_t ret = kStatus_SSS_Fail;
	smStatus_t status = SM_NOT_OK;

	if (!k_object || !store || !store->session || (!key_pair && !key_pub))
		return kStatus_SSS_Fail;

	s_ctx = &store->session->s_ctx;
	k_object->curve_id = key_pair ? key_pair->curve : key_pub->curve;
	type = k_object->isPersistant ? kSE05x_TransientType_Persistent :
				  kSE05x_TransientType_Transient;

	if (k_object->objectType != kSSS_KeyPart_Pair)
		goto label_public;

	public_keylen = key_pair->x_len + key_pair->y_len + 1;
	if (public_keylen > sizeof(buffer)) {
		EMSG("small buffer");
		goto exit;
	}
	memcpy(public_key, key_pair->x, key_pair->x_len);
	memcpy(public_key + key_pair->x_len, key_pair->y, key_pair->y_len);

	status = Se05x_API_WriteECKey(s_ctx,
				      &policy,
				      SE05x_MaxAttemps_UNLIMITED,
				      k_object->keyId,
				      (SE05x_ECCurve_t)key_pair->curve,
				      key_pair->d,
				      key_pair->d_len,
				      buffer,
				      public_keylen,
				      type,
				      kSE05x_KeyPart_Pair);

	ret = status == SM_OK ? kStatus_SSS_Success : kStatus_SSS_Fail;
	goto exit;

label_public:
	if (k_object->objectType != kSSS_KeyPart_Public)
		goto label_private;

	public_keylen = key_pub->x_len + key_pub->y_len + 1;
	if (public_keylen > sizeof(buffer)) {
		EMSG("small buffer");
		goto exit;
	}
	memcpy(public_key, key_pub->x, key_pub->x_len);
	memcpy(public_key + key_pub->x_len, key_pub->y, key_pub->y_len);

	status = Se05x_API_WriteECKey(s_ctx,
				      &policy,
				      SE05x_MaxAttemps_UNLIMITED,
				      k_object->keyId,
				      (SE05x_ECCurve_t)key_pub->curve,
				      NULL,
				      0,
				      buffer,
				      public_keylen,
				      type,
				      kSE05x_KeyPart_Public);
	ret = status == SM_OK ? kStatus_SSS_Success : kStatus_SSS_Fail;
	goto exit;

label_private:
	if (k_object->objectType != kSSS_KeyPart_Private)
		goto exit;

	status = Se05x_API_WriteECKey(s_ctx,
				      &policy,
				      SE05x_MaxAttemps_UNLIMITED,
				      k_object->keyId,
				      (SE05x_ECCurve_t)key_pair->curve,
				      key_pair->d,
				      key_pair->d_len,
				      NULL,
				      0,
				      type,
				      kSE05x_KeyPart_Private);
	ret = status == SM_OK ? kStatus_SSS_Success : kStatus_SSS_Fail;
	goto exit;

exit:
	return ret;
}

/*
 * @param store
 * @param k_object
 * @param key
 * @param keylen
 *
 * @return sss_status_t
 */
sss_status_t se050_key_store_get_ecc_key_bin(sss_se05x_key_store_t *store,
					     sss_se05x_object_t *k_object,
					     uint8_t *key, size_t *key_len)
{
	Se05xSession_t *s_ctx = NULL;
	sss_cipher_type_t cipher_type = kSSS_CipherType_NONE;
	sss_status_t ret = kStatus_SSS_Fail;
	smStatus_t status = SM_NOT_OK;
	uint8_t *key_buf = NULL;
	size_t key_buflen = 0;

	if (!store || !store->session || !k_object || !key || !key_len)
		return kStatus_SSS_Fail;

	s_ctx = &store->session->s_ctx;
	cipher_type = k_object->cipherType;

	switch (cipher_type) {
	case kSSS_CipherType_EC_NIST_P:
	case kSSS_CipherType_EC_NIST_K:
	case kSSS_CipherType_EC_BRAINPOOL:
	case kSSS_CipherType_EC_BARRETO_NAEHRIG:
	case kSSS_CipherType_EC_MONTGOMERY:
	case kSSS_CipherType_EC_TWISTED_ED:
		add_ecc_header(key, &key_buf, &key_buflen, k_object->curve_id);
		status = Se05x_API_ReadObject(s_ctx, k_object->keyId,
					      0, 0, key_buf, key_len);
		if (status != SM_OK)
			goto exit;

		*key_len += key_buflen;

		/* return only the binary data */
		key_buflen = *key_len;
		get_ecc_raw_data(key, &key_buf, &key_buflen,
				 k_object->curve_id);
		*key_len = key_buflen;
		memcpy(key, key_buf, key_buflen);

		break;
	default:
		goto exit;
	}

	ret = kStatus_SSS_Success;
exit:
	return ret;
}

/*
 * @param session
 * @param id
 * @param pub_key
 * @param secret
 * @param len
 *
 * @return sss_status_t
 */
sss_status_t se050_ecc_gen_shared_secret(pSe05xSession_t ctx,
					 uint32_t kid,
					 struct ecc_public_key_bin *key_pub,
					 uint8_t *secret, unsigned long *len)
{
	uint8_t key[256] = { 0x04 }; /* tag */
	smStatus_t status = SM_OK;
	uint8_t *p = key + 1;
	size_t key_len = 0;

	key_len = key_pub->x_len + key_pub->y_len + 1;
	if (key_len > sizeof(key)) {
		EMSG("small buffer");
		return kStatus_SSS_Fail;
	}

	memcpy(p, key_pub->x, key_pub->x_len);
	p += key_pub->x_len;
	memcpy(p, key_pub->y, key_pub->y_len);
	status = Se05x_API_ECGenSharedSecret(ctx, kid, key, key_len,
					     secret, len);
	if (status != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

/*
 * @param session_ctx
 * @param p
 * @param type
 *
 * @return sss_status_t
 */
sss_status_t  se050_get_free_memory(pSe05xSession_t ctx, uint16_t *p,
				    SE05x_MemoryType_t type)
{
	smStatus_t ret = SM_OK;

	if (!p || !ctx)
		return kStatus_SSS_Fail;

	ret = Se05x_API_GetFreeMemory(ctx, type, p);
	if (ret != SM_OK)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

/*
 * @param ctx
 * @param cmd
 *
 * @return sss_status_t
 *
 */
sss_status_t se050_scp03_send_rotate_cmd(pSe05xSession_t ctx,
					 struct s050_scp_rotate_cmd *cmd)
{
	uint8_t rsp[64] = { 0 };
	size_t rsp_len = sizeof(rsp);
	tlvHeader_t hdr = {
		.hdr = { [0] = 0x80, /* GP_CLA_BYTE   */
			 [1] = 0xd8, /* GP_INS_PUTKEY */
			 [2] = 0,
			 [3] = PUT_KEYS_KEY_IDENTIFIER,
		},
	};
	smStatus_t st = SM_NOT_OK;

	if (!ctx || !cmd)
		return kStatus_SSS_Fail;

	/* set the version of the key to replace */
	hdr.hdr[2] = cmd->cmd[0];

	st = DoAPDUTxRx_s_Case4(ctx, &hdr, cmd->cmd, cmd->cmd_len,
				rsp, &rsp_len);

	st = (rsp[rsp_len - 2] << 8) + rsp[rsp_len - 1];
	if (st != SM_OK)
		goto error;

	if (!memcmp(rsp, cmd->kcv, cmd->kcv_len)) {
		IMSG("rotation successful");
		return kStatus_SSS_Success;
	}

	EMSG("rotation failed: invalid check values");
error:
	EMSG("rotation error");
	return kStatus_SSS_Fail;
}
