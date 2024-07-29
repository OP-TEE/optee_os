// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2024 HiSilicon Limited.
 * Kunpeng hardware accelerator sec authenc algorithm implementation.
 */

#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>

#include "sec_authenc.h"
#include "sec_cipher.h"
#include "sec_hash.h"
#include "sec_main.h"

static enum hisi_drv_status sec_aead_bd_fill(void *bd, void *msg)
{
	struct authenc_ctx *ae_ctx = msg;
	struct hisi_sec_sqe *sqe = bd;
	uint8_t scene = 0;
	uint8_t de = 0;

	sqe->type_auth_cipher = BD_TYPE2 | SHIFT_U32(NO_AUTH, SEC_AUTH_OFFSET);
	scene = SHIFT_U32(SCENE_NOTHING, SEC_SCENE_OFFSET);
	de = SHIFT_U32(DATA_DST_ADDR_ENABLE, SEC_DE_OFFSET);
	sqe->sds_sa_type = de | scene;
	sqe->type2.cipher_src_offset = ae_ctx->aad.length;
	sqe->type2.icvw_kmode = SHIFT_U32(ae_ctx->c_key_len, SEC_CKEY_OFFSET) |
				SHIFT_U32(ae_ctx->mode, SEC_CMODE_OFFSET) |
				ae_ctx->tag_len;
	sqe->type2.clen_ivhlen = ae_ctx->payload_len;
	sqe->type2.alen_ivllen = ae_ctx->aad.length;
	sqe->type2.c_alg = ae_ctx->algo;

	if (ae_ctx->encrypt) {
		sqe->type_auth_cipher |= SHIFT_U32(CIPHER_ENCRYPT,
						   SEC_CIPHER_OFFSET);
		sqe->sds_sa_type |= SEC_CIPHER_THEN_DIGEST;
	} else {
		sqe->type_auth_cipher |= SHIFT_U32(CIPHER_DECRYPT,
						   SEC_CIPHER_OFFSET);
		sqe->sds_sa_type |= SEC_DIGEST_THEN_CIPHER;
	}

	sqe->type2.data_dst_addr = ae_ctx->dst_dma;
	sqe->type2.data_src_addr = ae_ctx->src_dma;
	sqe->type2.c_ivin_addr = ae_ctx->civ_dma;
	sqe->type2.c_key_addr = ae_ctx->key_dma;
	sqe->type2.mac_addr = ae_ctx->tag_dma;
	sqe->type2.a_ivin_addr = ae_ctx->aiv_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_aead_bd_parse(void *bd, void *msg)
{
	struct hisi_sec_sqe *sqe = bd;
	struct authenc_ctx *ctx = msg;
	uint16_t done = 0;

	ctx->result = SEC_GET_FIELD(sqe->type2.done_flag, SEC_ICV_MASK, 1);
	done = SEC_GET_FIELD(sqe->type2.done_flag, SEC_DONE_MASK, 0);
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		EMSG("SEC BD2 fail! done=%#"PRIx16", etype=%#"PRIx8,
		     done, sqe->type2.error_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_aead_bd3_fill(void *bd, void *msg)
{
	struct authenc_ctx *ae_ctx = msg;
	struct hisi_sec_bd3_sqe *sqe = bd;

	sqe->bd_param = BD_TYPE3 | SHIFT_U32(SCENE_NOTHING,
					     SEC_SCENE_OFFSET_V3) |
			SHIFT_U32(DATA_DST_ADDR_ENABLE, SEC_DE_OFFSET_V3);
	sqe->auth_mac_key = NO_AUTH;
	sqe->cipher_src_offset = ae_ctx->aad.length;
	sqe->c_icv_key = SHIFT_U32(ae_ctx->c_key_len, SEC_CKEY_OFFSET_V3) |
			 SHIFT_U32(ae_ctx->tag_len, SEC_ICV_LEN_OFFSET_V3);
	sqe->c_len_ivin = ae_ctx->payload_len;

	sqe->a_len_key = ae_ctx->aad.length;
	sqe->c_mode_alg = ae_ctx->mode |
			  SHIFT_U32(ae_ctx->algo, SEC_CALG_OFFSET_V3);

	if (ae_ctx->encrypt) {
		sqe->c_icv_key |= CIPHER_ENCRYPT;
		sqe->huk_iv_seq = SHIFT_U32(SEC_CIPHER_THEN_DIGEST,
					    SEC_SEQ_OFFSET_V3);
	} else {
		sqe->c_icv_key |= CIPHER_DECRYPT;
		sqe->huk_iv_seq = SHIFT_U32(SEC_DIGEST_THEN_CIPHER,
					    SEC_SEQ_OFFSET_V3);
	}

	sqe->no_scene.c_ivin_addr = ae_ctx->civ_dma;
	sqe->data_dst_addr = ae_ctx->dst_dma;
	sqe->data_src_addr = ae_ctx->src_dma;
	sqe->c_key_addr = ae_ctx->key_dma;
	sqe->mac_addr = ae_ctx->tag_dma;
	sqe->a_ivin_addr = ae_ctx->aiv_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_aead_bd3_parse(void *bd, void *msg)
{
	struct hisi_sec_bd3_sqe *sqe = bd;
	struct authenc_ctx *ctx = msg;
	uint16_t done = 0;

	ctx->result = SEC_GET_FIELD(sqe->done_flag, SEC_ICV_MASK, 1);
	done = SEC_GET_FIELD(sqe->done_flag, SEC_DONE_MASK, 0);
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		EMSG("SEC BD3 fail! done=%#"PRIx16", etype=%#"PRIx8,
		     done, sqe->error_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result sec_do_aead_task(struct hisi_qp *qp, void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hisi_qp_send(qp, msg);
	if (ret) {
		EMSG("Fail to send task, ret=%d", ret);
		return TEE_ERROR_BAD_STATE;
	}

	ret = hisi_qp_recv_sync(qp, msg);
	if (ret) {
		EMSG("Recv task error, ret=%d", ret);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result authenc_algo_check(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_GCM:
	case TEE_ALG_AES_CCM:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static uint8_t crypto_set_alg(uint32_t alg)
{
	switch (alg) {
	case TEE_MAIN_ALGO_AES:
		return C_ALG_AES;
	default:
		return 0;
	}
}

static uint8_t crypto_set_mode(uint32_t mode)
{
	switch (mode) {
	case TEE_CHAIN_MODE_CCM:
		return C_MODE_CCM;
	case TEE_CHAIN_MODE_GCM:
		return C_MODE_GCM;
	default:
		return 0;
	}
}

static TEE_Result sec_authenc_ctx_allocate(void **ctx, uint32_t algo)
{
	struct crypto_authenc_ctx *ae_soft_ctx = NULL;
	struct authenc_ctx *ae_drv_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!ctx) {
		EMSG("ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = authenc_algo_check(algo);
	if (ret)
		return ret;

	ae_drv_ctx = calloc(1, sizeof(struct authenc_ctx));
	if (!ae_drv_ctx) {
		EMSG("Fail to calloc ae_drv_ctx");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ae_drv_ctx->algo = crypto_set_alg(TEE_ALG_GET_MAIN_ALG(algo));
	ae_drv_ctx->mode = crypto_set_mode(TEE_ALG_GET_CHAIN_MODE(algo));

	ret = crypto_aes_gcm_alloc_ctx(&ae_soft_ctx);
	if (ret) {
		EMSG("soft ctx is NULL");
		goto free_ctx;
	}

	ae_drv_ctx->ae_soft_ctx = ae_soft_ctx;
	ae_drv_ctx->is_hw_supported = true;

	ae_drv_ctx->qp = sec_create_qp(HISI_QM_CHANNEL_TYPE0);
	if (!ae_drv_ctx->qp) {
		ret = TEE_ERROR_BUSY;
		goto free_soft_ctx;
	}

	if (ae_drv_ctx->qp->qm->version == HISI_QM_HW_V2) {
		ae_drv_ctx->qp->fill_sqe = sec_aead_bd_fill;
		ae_drv_ctx->qp->parse_sqe = sec_aead_bd_parse;
	} else {
		ae_drv_ctx->qp->fill_sqe = sec_aead_bd3_fill;
		ae_drv_ctx->qp->parse_sqe = sec_aead_bd3_parse;
	}

	*ctx = ae_drv_ctx;

	return TEE_SUCCESS;

free_soft_ctx:
	ae_soft_ctx->ops->free_ctx(ae_soft_ctx);
free_ctx:
	free(ae_drv_ctx);
	return ret;
}

static void sec_authenc_ctx_free(void *ctx)
{
	struct authenc_ctx *ae_drv_ctx = ctx;

	if (!ae_drv_ctx)
		return;

	ae_drv_ctx->ae_soft_ctx->ops->free_ctx(ae_drv_ctx->ae_soft_ctx);

	hisi_qm_release_qp(ae_drv_ctx->qp);
	memzero_explicit(ae_drv_ctx->key, ae_drv_ctx->key_len);

	if (ae_drv_ctx->src.data) {
		free(ae_drv_ctx->src.data);
		ae_drv_ctx->src.data = NULL;
	}

	if (ae_drv_ctx->dst.data) {
		free(ae_drv_ctx->dst.data);
		ae_drv_ctx->dst.data = NULL;
	}

	free(ae_drv_ctx);
}

static TEE_Result authenc_init_params_check(struct drvcrypt_authenc_init *dinit)
{
	if (!dinit) {
		EMSG("dinit is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!dinit->ctx) {
		EMSG("ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!dinit->key.length || !dinit->key.data) {
		EMSG("key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!dinit->nonce.data || !dinit->nonce.length) {
		EMSG("iv is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static bool is_hw_supported(struct drvcrypt_authenc_init *dinit)
{
	struct authenc_ctx *ae_drv_ctx = dinit->ctx;

	if (ae_drv_ctx->mode == C_MODE_GCM) {
		if (dinit->nonce.length != GCM_IV_SIZE)
			return false;

		if (dinit->aad_len > MAX_GCM_AAD_SIZE) {
			EMSG("Invalid aad len");
			return false;
		}

		if (dinit->tag_len < SEC_MIN_GCM_TAG_LEN ||
		    dinit->tag_len > SEC_MAX_TAG_LEN) {
			EMSG("Invalid tag len");
			return false;
		}
	} else {
		if (dinit->nonce.length < MIN_CCM_NONCE_SIZE ||
		    dinit->nonce.length > MAX_CCM_NONCE_SIZE) {
			EMSG("Invalid nonce len");
			return false;
		}

		if (dinit->aad_len > MAX_CCM_AAD_SIZE) {
			EMSG("Invalid aad len");
			return false;
		}

		if (dinit->tag_len < SEC_MIN_CCM_TAG_LEN ||
		    dinit->tag_len > SEC_MAX_TAG_LEN ||
		    dinit->tag_len % TAG_ALIGN) {
			EMSG("Invalid tag len");
			return false;
		}
	}

	if (dinit->payload_len + dinit->aad_len > SEC_MAX_AEAD_LENGTH ||
	    (ae_drv_ctx->qp->qm->version == HISI_QM_HW_V2 &&
	    dinit->payload_len == 0)) {
		EMSG("Invalid src len");
		return false;
	}

	return true;
}

static TEE_Result sec_aead_set_key(struct drvcrypt_authenc_init *dinit)
{
	struct authenc_ctx *ae_drv_ctx = dinit->ctx;

	ae_drv_ctx->key_len = dinit->key.length;

	switch (ae_drv_ctx->key_len) {
	case AES_KEYSIZE_128:
		ae_drv_ctx->c_key_len = CKEY_LEN_128_BIT;
		break;
	case AES_KEYSIZE_192:
		ae_drv_ctx->c_key_len = CKEY_LEN_192_BIT;
		break;
	case AES_KEYSIZE_256:
		ae_drv_ctx->c_key_len = CKEY_LEN_256_BIT;
		break;
	default:
		EMSG("Invalid AES key size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(ae_drv_ctx->key, dinit->key.data, dinit->key.length);

	return TEE_SUCCESS;
}

static TEE_Result sec_aead_set_iv(struct drvcrypt_authenc_init *dinit)
{
	struct authenc_ctx *ae_drv_ctx = dinit->ctx;
	uint32_t data_size = dinit->payload_len;
	uint8_t adata = 0;
	uint8_t flags = 0;
	uint8_t cm = 0;
	uint8_t cl = 0;

	ae_drv_ctx->civ_len = MAX_IV_SIZE;
	if (ae_drv_ctx->mode == C_MODE_GCM) {
		ae_drv_ctx->civ_len = dinit->nonce.length;
		memcpy(ae_drv_ctx->civ, dinit->nonce.data, dinit->nonce.length);
		return TEE_SUCCESS;
	}

	if (dinit->aad_len)
		adata = AAD_NOT_NULL;

	cm = ((dinit->tag_len - IV_CM_CAL_NUM) / IV_CM_CAL_NUM) & IV_CL_MASK;
	cl = IV_CL_CAL_NUM - dinit->nonce.length;
	flags = cl | SHIFT_U32(cm, IV_CM_OFFSET) |
		SHIFT_U32(adata, IV_FLAGS_OFFSET);

	memcpy(ae_drv_ctx->civ + NONCE_OFFSET, dinit->nonce.data,
	       dinit->nonce.length);
	memcpy(ae_drv_ctx->aiv + NONCE_OFFSET, dinit->nonce.data,
	       dinit->nonce.length);

	ae_drv_ctx->aiv[0] = flags;
	ae_drv_ctx->aiv[IV_LAST_BYTE1] = data_size & IV_LAST_BYTE_MASK;
	data_size >>= IV_BYTE_OFFSET;
	ae_drv_ctx->aiv[IV_LAST_BYTE2] = data_size & IV_LAST_BYTE_MASK;
	data_size >>= IV_BYTE_OFFSET;
	ae_drv_ctx->aiv[IV_LAST_BYTE3] = data_size & IV_LAST_BYTE_MASK;

	ae_drv_ctx->civ[0] = cl;
	ae_drv_ctx->civ[MAX_IV_SIZE - 1] = IV_CTR_INIT;

	return TEE_SUCCESS;
}

static TEE_Result sec_aead_get_dma(struct authenc_ctx *ae_drv_ctx)
{
	ae_drv_ctx->key_dma = virt_to_phys(ae_drv_ctx->key);
	ae_drv_ctx->civ_dma = virt_to_phys(ae_drv_ctx->civ);
	ae_drv_ctx->tag_dma = virt_to_phys(ae_drv_ctx->tag);
	ae_drv_ctx->src_dma = virt_to_phys(ae_drv_ctx->src.data);
	ae_drv_ctx->dst_dma = virt_to_phys(ae_drv_ctx->dst.data);

	if (ae_drv_ctx->mode == C_MODE_GCM)
		return TEE_SUCCESS;
	ae_drv_ctx->aiv_dma = virt_to_phys(ae_drv_ctx->aiv);

	return TEE_SUCCESS;
}

static TEE_Result sec_aead_data_alloc(struct authenc_ctx *ae_drv_ctx)
{
	ae_drv_ctx->src.length = ae_drv_ctx->payload_len +
				 ae_drv_ctx->aad.length;
	ae_drv_ctx->src.data = malloc(ae_drv_ctx->src.length);
	if (!ae_drv_ctx->src.data) {
		EMSG("Fail to malloc src");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ae_drv_ctx->dst.length = ae_drv_ctx->src.length;
	ae_drv_ctx->dst.data = malloc(ae_drv_ctx->dst.length);
	if (!ae_drv_ctx->dst.data) {
		EMSG("Fail to malloc dst");
		free(ae_drv_ctx->src.data);
		ae_drv_ctx->src.data = NULL;
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static TEE_Result ae_soft_calc_init(struct authenc_ctx *ae_drv_ctx,
				    struct drvcrypt_authenc_init *dinit)
{
	struct crypto_authenc_ctx *ae_soft_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationMode mode = 0;

	if (ae_drv_ctx->algo == C_ALG_AES && ae_drv_ctx->mode == C_MODE_GCM) {
		ae_drv_ctx->is_hw_supported = false;
		ae_soft_ctx = ae_drv_ctx->ae_soft_ctx;
		if (!dinit->encrypt)
			mode = 1;
		ret = ae_soft_ctx->ops->init(ae_soft_ctx, mode,
			dinit->key.data, dinit->key.length,
			dinit->nonce.data, dinit->nonce.length,
			dinit->tag_len, dinit->aad_len,
			dinit->payload_len);
		if (ret)
			EMSG("Fail to init by soft ctx");

		return ret;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result sec_authenc_initialize(struct drvcrypt_authenc_init *dinit)
{
	struct authenc_ctx *ae_drv_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;
	bool hw_support = false;

	ret = authenc_init_params_check(dinit);
	if (ret)
		return ret;

	ae_drv_ctx = dinit->ctx;
	hw_support = is_hw_supported(dinit);
	if (!hw_support)
		return ae_soft_calc_init(ae_drv_ctx, dinit);

	ae_drv_ctx->encrypt = dinit->encrypt;
	ae_drv_ctx->payload_len = dinit->payload_len;
	ae_drv_ctx->aad.length = dinit->aad_len;
	ae_drv_ctx->tag_len = dinit->tag_len;

	ret = sec_aead_set_key(dinit);
	if (ret)
		return ret;

	ret = sec_aead_set_iv(dinit);
	if (ret)
		goto clean_key;

	ret = sec_aead_data_alloc(ae_drv_ctx);
	if (ret)
		goto clean_key;

	ret = sec_aead_get_dma(ae_drv_ctx);
	if (ret)
		goto free_data;

	return TEE_SUCCESS;
free_data:
	if (ae_drv_ctx->src.data) {
		free(ae_drv_ctx->src.data);
		ae_drv_ctx->src.data = NULL;
	}
	if (ae_drv_ctx->dst.data) {
		free(ae_drv_ctx->dst.data);
		ae_drv_ctx->src.data = NULL;
	}
clean_key:
	memzero_explicit(ae_drv_ctx->key, sizeof(ae_drv_ctx->key));
	return ret;
}

static TEE_Result
sec_authenc_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct crypto_authenc_ctx *ae_soft_ctx = NULL;
	struct authenc_ctx *ae_drv_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!dupdate || !dupdate->ctx) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ae_drv_ctx = dupdate->ctx;
	if (!ae_drv_ctx->is_hw_supported) {
		ae_soft_ctx = ae_drv_ctx->ae_soft_ctx;
		ret = ae_soft_ctx->ops->update_aad(ae_soft_ctx,
			dupdate->aad.data, dupdate->aad.length);
		if (ret)
			EMSG("Fail to update aad by soft ctx");

		return ret;
	}

	if (dupdate->aad.length + ae_drv_ctx->src_offset >
	    ae_drv_ctx->src.length) {
		EMSG("Invalid aad length");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/*
	 * Both aad and ptx need to be filled in the src field.
	 * Here, aad is placed in the header of the src field.
	 */
	memcpy(ae_drv_ctx->src.data + ae_drv_ctx->src_offset,
	       dupdate->aad.data, dupdate->aad.length);
	ae_drv_ctx->src_offset += dupdate->aad.length;

	return TEE_SUCCESS;
}

static TEE_Result update_params_check(struct drvcrypt_authenc_update_payload *d)
{
	struct authenc_ctx *ae_drv_ctx = NULL;

	ae_drv_ctx = d->ctx;
	if (!ae_drv_ctx->src.data || !ae_drv_ctx->dst.data) {
		EMSG("Invalid input/output data");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (d->src.length + ae_drv_ctx->src_offset > ae_drv_ctx->src.length) {
		EMSG("Invalid update src length");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (d->dst.length + ae_drv_ctx->src_offset > ae_drv_ctx->dst.length) {
		EMSG("Invalid update dst length");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result
sec_authenc_update_payload(struct drvcrypt_authenc_update_payload *d)
{
	struct crypto_authenc_ctx *ae_soft_ctx = NULL;
	struct authenc_ctx *ae_drv_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!d || !d->ctx) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ae_drv_ctx = d->ctx;
	if (!ae_drv_ctx->is_hw_supported) {
		ae_soft_ctx = ae_drv_ctx->ae_soft_ctx;
		ret = ae_soft_ctx->ops->update_payload(ae_soft_ctx,
				(TEE_OperationMode)(d->encrypt == 0),
				d->src.data, d->src.length, d->dst.data);
		if (ret)
			EMSG("Fail to update payload by soft ctx");

		return ret;
	}

	ret = update_params_check(d);
	if (ret)
		return ret;

	memcpy(ae_drv_ctx->src.data + ae_drv_ctx->src_offset,
	       d->src.data, d->src.length);

	ret = sec_do_aead_task(ae_drv_ctx->qp, ae_drv_ctx);
	if (ret)
		return ret;

	memcpy(d->dst.data, ae_drv_ctx->dst.data + ae_drv_ctx->src_offset,
	       d->dst.length);
	ae_drv_ctx->src_offset += d->src.length;

	return TEE_SUCCESS;
}

static TEE_Result final_params_check(struct drvcrypt_authenc_final *dfinal)
{
	struct authenc_ctx *ae_drv_ctx = dfinal->ctx;

	if (!ae_drv_ctx->src.data || !ae_drv_ctx->dst.data) {
		EMSG("Invalid input/output data");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (dfinal->src.length + ae_drv_ctx->src_offset >
	    ae_drv_ctx->src.length) {
		EMSG("Invalid dfinal src length");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (dfinal->dst.length + ae_drv_ctx->src_offset >
	    ae_drv_ctx->dst.length) {
		EMSG("Invalid dfinal dst length");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (dfinal->tag.length > SEC_MAX_TAG_LEN) {
		EMSG("Invalid dfinal tag length");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_authenc_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	struct crypto_authenc_ctx *ae_soft_ctx = NULL;
	struct authenc_ctx *ae_drv_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!dfinal || !dfinal->ctx) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ae_drv_ctx = dfinal->ctx;
	if (!ae_drv_ctx->is_hw_supported) {
		ae_soft_ctx = ae_drv_ctx->ae_soft_ctx;
		ret = ae_soft_ctx->ops->enc_final(ae_soft_ctx,
			dfinal->src.data, dfinal->src.length,
			dfinal->dst.data, dfinal->tag.data,
			&dfinal->tag.length);
		if (ret)
			EMSG("Fail to do enc final by soft ctx");

		return ret;
	}

	ret = final_params_check(dfinal);
	if (ret)
		return ret;
	memcpy(ae_drv_ctx->src.data + ae_drv_ctx->src_offset, dfinal->src.data,
	       dfinal->src.length);

	ret = sec_do_aead_task(ae_drv_ctx->qp, ae_drv_ctx);

	memcpy(dfinal->tag.data, ae_drv_ctx->tag, dfinal->tag.length);
	memcpy(dfinal->dst.data, ae_drv_ctx->dst.data + ae_drv_ctx->src_offset,
	       dfinal->dst.length);

	return ret;
}

static TEE_Result sec_authenc_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	struct crypto_authenc_ctx *ae_soft_ctx = NULL;
	struct authenc_ctx *ae_drv_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!dfinal || !dfinal->ctx) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ae_drv_ctx = dfinal->ctx;
	if (!ae_drv_ctx->is_hw_supported) {
		ae_soft_ctx = ae_drv_ctx->ae_soft_ctx;
		ret =  ae_soft_ctx->ops->dec_final(ae_soft_ctx,
			dfinal->src.data, dfinal->src.length,
			dfinal->dst.data, dfinal->tag.data,
			dfinal->tag.length);
		if (ret)
			EMSG("Fail to do dec final by soft ctx");

		return ret;
	}

	ret = final_params_check(dfinal);
	if (ret)
		return ret;
	memcpy(ae_drv_ctx->src.data + ae_drv_ctx->src_offset, dfinal->src.data,
	       dfinal->src.length);
	memcpy(ae_drv_ctx->tag, dfinal->tag.data, dfinal->tag.length);

	ret = sec_do_aead_task(ae_drv_ctx->qp, ae_drv_ctx);
	if (ret)
		return ret;

	memcpy(dfinal->dst.data, ae_drv_ctx->dst.data + ae_drv_ctx->src_offset,
	       dfinal->dst.length);
	if (ae_drv_ctx->result == SEC_TAG_ERR) {
		EMSG("Integrity check failed");
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static void sec_authenc_do_final(void *ctx __unused)
{
}

static void sec_authenc_copy_state(void *dst_ctx, void *src_ctx)
{
	struct authenc_ctx *dst = dst_ctx;
	struct authenc_ctx *src = src_ctx;
	TEE_Result ret = TEE_SUCCESS;

	if (!src->is_hw_supported) {
		dst->is_hw_supported = false;
		src->ae_soft_ctx->ops->copy_state(dst->ae_soft_ctx,
						  src->ae_soft_ctx);
		return;
	}

	dst->algo = src->algo;
	dst->mode = src->mode;
	dst->encrypt = src->encrypt;
	dst->key_len = src->key_len;
	dst->tag_len = src->tag_len;
	dst->c_key_len = src->c_key_len;
	dst->aad.length = src->aad.length;
	dst->src_offset = src->src_offset;
	dst->payload_len = src->payload_len;
	dst->is_hw_supported = src->is_hw_supported;
	memcpy(dst->key, src->key, src->key_len);
	memcpy(dst->civ, src->civ, src->civ_len);
	/* The len of aiv is always MAX_IV_SIZE */
	memcpy(dst->aiv, src->aiv, MAX_IV_SIZE);
	ret = sec_aead_data_alloc(dst);
	if (ret)
		return;
	memcpy(dst->src.data, src->src.data,
	       src->aad.length + src->payload_len);
	memcpy(dst->dst.data, src->dst.data,
	       src->aad.length + src->payload_len);

	ret = sec_aead_get_dma(dst);
	if (ret) {
		memzero_explicit(dst->key, dst->key_len);
		free(dst->src.data);
		dst->src.data = NULL;
		free(dst->dst.data);
		dst->dst.data = NULL;
	}
}

static struct drvcrypt_authenc driver_authenc = {
	.alloc_ctx = sec_authenc_ctx_allocate,
	.free_ctx = sec_authenc_ctx_free,
	.init = sec_authenc_initialize,
	.update_aad = sec_authenc_update_aad,
	.update_payload = sec_authenc_update_payload,
	.enc_final = sec_authenc_enc_final,
	.dec_final = sec_authenc_dec_final,
	.final = sec_authenc_do_final,
	.copy_state = sec_authenc_copy_state,
};

static TEE_Result sec_authenc_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_authenc(&driver_authenc);
	if (ret)
		EMSG("Sec authenc register to crypto fail ret=%#"PRIx32, ret);

	return ret;
}
driver_init(sec_authenc_init);
