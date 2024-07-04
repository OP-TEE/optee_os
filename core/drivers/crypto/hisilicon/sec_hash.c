// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2024 HiSilicon Limited.
 * Kunpeng hardware accelerator sec hash algorithm implementation.
 */

#include <drvcrypt_hash.h>
#include <initcall.h>

#include "sec_hash.h"
#include "sec_main.h"

static enum hisi_drv_status sec_digest_set_hmac_key(struct hashctx *ctx,
						    struct hisi_sec_sqe *sqe)
{
	if (ctx->key_len > SEC_DIGEST_MAX_KEY_SIZE || !ctx->key_len) {
		EMSG("Invalid digest key len(%ld)", ctx->key_len);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	/* If the length of key is not word-aligned, increment by 1 */
	sqe->type2.mac_key_alg |= SHIFT_U64(DIV_ROUND_UP(ctx->key_len,
							 SEC_ENCODE_BYTES),
					    SEC_AKEY_OFFSET);
	sqe->type2.a_key_addr = ctx->key_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void sec_digest_fill_long_bd2(struct hashctx *ctx,
				     struct hisi_sec_sqe *sqe)
{
	uint64_t total_bits = 0;

	if (ctx->has_next && !ctx->iv_len) {
		/* LONG BD FIRST */
		sqe->ai_apd_cs |= AI_GEN_INNER;
		sqe->ai_apd_cs |= SHIFT_U32(AUTHPAD_NOPAD, SEC_APAD_OFFSET);
		ctx->iv_len = ctx->mac_len;
	} else if (ctx->has_next && ctx->iv_len) {
		/* LONG BD MIDDLE */
		sqe->ai_apd_cs |= AI_GEN_IVIN_ADDR;
		sqe->ai_apd_cs |= SHIFT_U32(AUTHPAD_NOPAD, SEC_APAD_OFFSET);
		sqe->type2.a_ivin_addr = sqe->type2.mac_addr;
		ctx->iv_len = ctx->mac_len;
	} else if (!ctx->has_next && ctx->iv_len) {
		/* LONG BD END */
		sqe->ai_apd_cs |= AI_GEN_IVIN_ADDR;
		sqe->ai_apd_cs |= SHIFT_U32(AUTHPAD_PAD, SEC_APAD_OFFSET);
		sqe->type2.a_ivin_addr = sqe->type2.mac_addr;
		total_bits = ctx->long_data_len * BYTE_BITS;
		sqe->type2.long_a_data_len = total_bits;
		ctx->iv_len = 0;
	} else {
		/* SHORT BD */
		ctx->iv_len = 0;
	}
}

static struct crypto_hash *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	return container_of(ctx, struct crypto_hash, hash_ctx);
}

static uint32_t sec_digest_get_alg_type(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_MD5:
		return A_ALG_MD5;
	case TEE_ALG_HMAC_MD5:
		return A_ALG_HMAC_MD5;
	case TEE_ALG_SHA1:
		return A_ALG_SHA1;
	case TEE_ALG_HMAC_SHA1:
		return A_ALG_HMAC_SHA1;
	case TEE_ALG_SHA224:
		return A_ALG_SHA224;
	case TEE_ALG_HMAC_SHA224:
		return A_ALG_HMAC_SHA224;
	case TEE_ALG_SM3:
		return A_ALG_SM3;
	case TEE_ALG_HMAC_SM3:
		return A_ALG_HMAC_SM3;
	case TEE_ALG_SHA256:
		return A_ALG_SHA256;
	case TEE_ALG_HMAC_SHA256:
		return A_ALG_HMAC_SHA256;
	case TEE_ALG_SHA384:
		return A_ALG_SHA384;
	case TEE_ALG_HMAC_SHA384:
		return A_ALG_HMAC_SHA384;
	case TEE_ALG_SHA512:
		return A_ALG_SHA512;
	case TEE_ALG_HMAC_SHA512:
		return A_ALG_HMAC_SHA512;
	default:
		return A_ALG_MAX;
	}
}

static enum hisi_drv_status sec_digest_fill_sqe(void *bd, void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct hisi_sec_sqe *sqe = bd;
	struct hashctx *ctx = msg;
	uint32_t alg_type = 0;

	if (!ctx->in_len) {
		EMSG("Digest bd2 not support 0 packet");
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	sqe->type_auth_cipher = BD_TYPE2;
	sqe->sds_sa_type = SHIFT_U32(SCENE_NOTHING, SEC_SCENE_OFFSET);
	sqe->type_auth_cipher |= SHIFT_U32(AUTH_MAC_CALCULATE, SEC_AUTH_OFFSET);
	sqe->type2.alen_ivllen = ctx->in_len;

	sqe->type2.data_src_addr = ctx->in_dma;
	sqe->type2.mac_addr = ctx->out_dma;
	sqe->type2.mac_key_alg |= ctx->mac_len / SEC_ENCODE_BYTES;

	if (ctx->mode == WCRYPTO_DIGEST_HMAC) {
		ret = sec_digest_set_hmac_key(ctx, sqe);
		if (ret)
			return ret;
	}

	alg_type = sec_digest_get_alg_type(ctx->algo);
	if (alg_type >= A_ALG_MAX) {
		EMSG("Fail to get digest alg type");
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}
	sqe->type2.mac_key_alg |= SHIFT_U32(alg_type, SEC_AEAD_ALG_OFFSET);

	sec_digest_fill_long_bd2(ctx, sqe);

	return ret;
}

static enum hisi_drv_status
sec_digest_set_hmac_bd3_key(struct hashctx *ctx, struct hisi_sec_bd3_sqe *sqe)
{
	if (ctx->key_len > SEC_DIGEST_MAX_KEY_SIZE || !ctx->key_len) {
		EMSG("Invalid digest key len(%ld)", ctx->key_len);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	/* If the length of key is not word-aligned, increment by 1 */
	sqe->auth_mac_key |= SHIFT_U64(DIV_ROUND_UP(ctx->key_len,
						    SEC_ENCODE_BYTES),
				       SEC_AKEY_OFFSET_V3);
	sqe->a_key_addr = ctx->key_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void sec_digest_fill_long_bd3(struct hashctx *ctx,
				     struct hisi_sec_bd3_sqe *sqe)
{
	uint64_t total_bits = 0;

	if (ctx->has_next && !ctx->iv_len) {
		/* LONG BD FIRST */
		sqe->auth_mac_key |= SHIFT_U32(AI_GEN_INNER,
					       SEC_AI_GEN_OFFSET_V3);
		sqe->stream_scene.auth_pad = AUTHPAD_NOPAD;
		ctx->iv_len = ctx->mac_len;
	} else if (ctx->has_next && ctx->iv_len) {
		/* LONG BD MIDDLE */
		sqe->auth_mac_key |= SHIFT_U32(AI_GEN_IVIN_ADDR,
					       SEC_AI_GEN_OFFSET_V3);
		sqe->stream_scene.auth_pad = AUTHPAD_NOPAD;
		sqe->a_ivin_addr = sqe->mac_addr;
		ctx->iv_len = ctx->mac_len;
	} else if (!ctx->has_next && ctx->iv_len) {
		/* LONG BD END */
		sqe->auth_mac_key |= SHIFT_U32(AI_GEN_IVIN_ADDR,
					       SEC_AI_GEN_OFFSET_V3);
		sqe->stream_scene.auth_pad = AUTHPAD_PAD;
		sqe->a_ivin_addr = sqe->mac_addr;
		total_bits = ctx->long_data_len * BYTE_BITS;
		sqe->stream_scene.long_a_data_len = total_bits;
		ctx->iv_len = 0;
	} else {
		/* SHORT BD */
		ctx->iv_len = 0;
	}
}

static enum hisi_drv_status sec_digest_fill_bd3_sqe(void *bd, void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct hisi_sec_bd3_sqe *sqe = bd;
	struct hashctx *ctx = msg;
	uint32_t alg_type = 0;

	sqe->bd_param = BD_TYPE3 | SHIFT_U32(ctx->scene, SEC_SCENE_OFFSET_V3);
	sqe->a_len_key = ctx->in_len;
	sqe->auth_mac_key = AUTH_MAC_CALCULATE;
	sqe->data_src_addr = ctx->in_dma;
	sqe->mac_addr = ctx->out_dma;

	if (ctx->mode == WCRYPTO_DIGEST_HMAC) {
		ret = sec_digest_set_hmac_bd3_key(ctx, sqe);
		if (ret)
			return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	sqe->auth_mac_key |= SHIFT_U64(ctx->mac_len / SEC_ENCODE_BYTES,
				       SEC_MAC_OFFSET_V3);
	alg_type = sec_digest_get_alg_type(ctx->algo);
	if (alg_type >= A_ALG_MAX) {
		EMSG("Fail to get digest bd3 alg");
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}
	sqe->auth_mac_key |= SHIFT_U32(alg_type, SEC_AUTH_ALG_OFFSET_V3);
	sec_digest_fill_long_bd3(ctx, sqe);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result sec_digest_do_task(struct hisi_qp *qp, void *msg)
{
	TEE_Result ret = TEE_SUCCESS;

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

static enum hisi_drv_status sec_parse_digest_sqe(void *bd, void *msg __unused)
{
	struct hisi_sec_sqe *sqe = bd;
	uint16_t done = 0;

	done = SEC_GET_FIELD(sqe->type2.done_flag, SEC_DONE_MASK, 0);
	if (done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		EMSG("SEC BD2 fail! done=%#"PRIx16", etype=%#"PRIx8,
		     done, sqe->type2.error_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_parse_digest_bd3_sqe(void *bd,
						     void *msg __unused)
{
	struct hisi_sec_bd3_sqe *sqe = bd;
	uint16_t done = 0;

	done = SEC_GET_FIELD(sqe->done_flag, SEC_DONE_MASK, 0);
	if (done != SEC_HW_TASK_DONE || sqe->error_type) {
		EMSG("SEC BD3 fail! done=%#"PRIx16", etype=%#"PRIx8,
		     done, sqe->error_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

TEE_Result hisi_sec_digest_ctx_init(struct hashctx *hash_ctx,
				    const uint8_t *key, size_t len)
{
	if (!hash_ctx) {
		EMSG("Input hash_ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash_ctx->in_len = 0;
	hash_ctx->iv_len = 0;
	hash_ctx->has_next = false;
	hash_ctx->long_data_len = 0;
	hash_ctx->scene = SCENE_NOTHING;

	/*
	 * In reset ctx scenarios, sec_hash_initialize will be called.
	 * To ensure in data is NULL, reset ctx need to free in data
	 * which is not NULL.
	 */
	free(hash_ctx->in);
	hash_ctx->in = NULL;

	if (len) {
		hash_ctx->key_len = len;
		memcpy(hash_ctx->key, key, len);
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_hash_initialize(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = NULL;
	struct hashctx *hash_ctx = NULL;

	if (!ctx) {
		EMSG("Input ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash = to_hash_ctx(ctx);
	hash_ctx = hash->ctx;

	return hisi_sec_digest_ctx_init(hash_ctx, NULL, 0);
}

TEE_Result hisi_sec_digest_do_update(struct hashctx *hash_ctx,
				     const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t left_size = 0;

	hash_ctx->long_data_len += len;

	if (!hash_ctx->in) {
		if (len <= SMALL_BUF_SIZE)
			hash_ctx->buf_len = SMALL_BUF_SIZE;
		else if (len <= MAX_AUTH_LENGTH)
			hash_ctx->buf_len = ROUNDUP(len, HISI_QM_ALIGN128);
		else
			hash_ctx->buf_len = MAX_AUTH_LENGTH;

		hash_ctx->in_len = 0;
		hash_ctx->in = malloc(hash_ctx->buf_len);
		if (!hash_ctx->in) {
			EMSG("Fail to alloc in data buf");
			return TEE_ERROR_OUT_OF_MEMORY;
		}
		hash_ctx->in_dma = virt_to_phys(hash_ctx->in);
	}

	while (len > 0) {
		if (hash_ctx->in_len + len <= hash_ctx->buf_len) {
			memcpy(hash_ctx->in + hash_ctx->in_len, data, len);
			hash_ctx->in_len += len;
			len = 0;
		} else {
			left_size = hash_ctx->buf_len - hash_ctx->in_len;
			memcpy(hash_ctx->in + hash_ctx->in_len, data,
			       left_size);
			hash_ctx->in_len = hash_ctx->buf_len;
			hash_ctx->scene = SCENE_STREAM;
			hash_ctx->has_next = true;
			data += left_size;
			len -= left_size;
			ret = sec_digest_do_task(hash_ctx->qp, hash_ctx);
			if (ret) {
				EMSG("Fail to do digest task! ret = %#"PRIx32,
				     ret);
				return ret;
			}
			hash_ctx->iv_len = hash_ctx->mac_len;
			hash_ctx->in_len = 0;
		}
	}
	return TEE_SUCCESS;
}

static TEE_Result sec_hash_do_update(struct crypto_hash_ctx *ctx,
				     const uint8_t *data, size_t len)
{
	struct crypto_hash *hash = NULL;
	struct hashctx *hash_ctx = NULL;

	if (!len) {
		IMSG("This is 0 len task, skip");
		return TEE_SUCCESS;
	}

	if (!ctx || (!data && len)) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash = to_hash_ctx(ctx);
	hash_ctx = hash->ctx;

	return hisi_sec_digest_do_update(hash_ctx, data, len);
}

TEE_Result hisi_sec_digest_do_final(struct hashctx *hash_ctx, uint8_t *digest,
				    size_t len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!digest || len == 0) {
		EMSG("Invalid input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (hash_ctx->mac_len & WORD_ALIGNMENT_MASK) {
		EMSG("Invalid digest out_bytes");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash_ctx->has_next = false;
	ret = sec_digest_do_task(hash_ctx->qp, hash_ctx);
	if (ret) {
		EMSG("Fail to do digest task! ret = %#"PRIx32, ret);
		return ret;
	}

	memcpy(digest, hash_ctx->out, MIN(hash_ctx->mac_len, len));

	return TEE_SUCCESS;
}

static TEE_Result sec_hash_do_final(struct crypto_hash_ctx *ctx,
				    uint8_t *digest, size_t len)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);
	struct hashctx *hash_ctx = hash->ctx;

	return hisi_sec_digest_do_final(hash_ctx, digest, len);
}

void hisi_sec_digest_ctx_free(struct hashctx *hash_ctx)
{
	hisi_qm_release_qp(hash_ctx->qp);

	free(hash_ctx->in);
	hash_ctx->in = NULL;

	memzero_explicit(hash_ctx->key, SEC_DIGEST_MAX_KEY_SIZE);

	free(hash_ctx);
}

static void sec_hash_ctx_free(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = NULL;
	struct hashctx *hash_ctx = NULL;

	if (!ctx)
		return;

	hash = to_hash_ctx(ctx);
	hash_ctx = hash->ctx;
	if (!hash_ctx)
		return;
	hisi_sec_digest_ctx_free(hash_ctx);

	hash->ctx = NULL;

	free(hash);
}

void hisi_sec_digest_copy_state(struct hashctx *out_hash_ctx,
				struct hashctx *in_hash_ctx)
{
	out_hash_ctx->iv_len = in_hash_ctx->iv_len;
	out_hash_ctx->buf_len = in_hash_ctx->buf_len;
	out_hash_ctx->key_len = in_hash_ctx->key_len;
	out_hash_ctx->has_next = in_hash_ctx->has_next;
	out_hash_ctx->long_data_len = in_hash_ctx->long_data_len;

	if (in_hash_ctx->in) {
		out_hash_ctx->in = malloc(out_hash_ctx->buf_len);
		if (!out_hash_ctx->in) {
			EMSG("Fail to alloc in buf");
			return;
		}
		out_hash_ctx->in_dma = virt_to_phys(out_hash_ctx->in);
		out_hash_ctx->in_len = in_hash_ctx->in_len;
		memcpy(out_hash_ctx->in, in_hash_ctx->in,
		       out_hash_ctx->buf_len);
	}

	memcpy(out_hash_ctx->iv, in_hash_ctx->iv, out_hash_ctx->iv_len);
	memcpy(out_hash_ctx->key, in_hash_ctx->key, out_hash_ctx->key_len);
}

static void sec_hash_copy_state(struct crypto_hash_ctx *out_ctx,
				struct crypto_hash_ctx *in_ctx)
{
	struct crypto_hash *out_hash = NULL;
	struct crypto_hash *in_hash = NULL;
	struct hashctx *out_hash_ctx = NULL;
	struct hashctx *in_hash_ctx = NULL;

	if (!out_ctx || !in_ctx) {
		EMSG("Invalid input parameters");
		return;
	}

	out_hash = to_hash_ctx(out_ctx);
	in_hash = to_hash_ctx(in_ctx);

	out_hash_ctx = out_hash->ctx;
	in_hash_ctx = in_hash->ctx;

	hisi_sec_digest_copy_state(out_hash_ctx, in_hash_ctx);
}

static struct crypto_hash_ops hash_ops = {
	.init = sec_hash_initialize,
	.update = sec_hash_do_update,
	.final = sec_hash_do_final,
	.free_ctx = sec_hash_ctx_free,
	.copy_state = sec_hash_copy_state,
};

static size_t sec_hash_get_mac_len(uint32_t type)
{
	switch (type) {
	case TEE_ALG_MD5:
	case TEE_ALG_HMAC_MD5:
		return HASH_MAC_LEN128;
	case TEE_ALG_SHA1:
	case TEE_ALG_HMAC_SHA1:
		return HASH_MAC_LEN160;
	case TEE_ALG_SHA224:
	case TEE_ALG_HMAC_SHA224:
		return HASH_MAC_LEN224;
	case TEE_ALG_SM3:
	case TEE_ALG_HMAC_SM3:
	case TEE_ALG_SHA256:
	case TEE_ALG_HMAC_SHA256:
		return HASH_MAC_LEN256;
	case TEE_ALG_SHA384:
	case TEE_ALG_HMAC_SHA384:
		return HASH_MAC_LEN384;
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_SHA512:
		return HASH_MAC_LEN512;
	default:
		return 0;
	}
}

static TEE_Result sec_hash_get_dma(struct hashctx *hash_ctx)
{
	hash_ctx->key_dma = virt_to_phys(hash_ctx->key);
	if (!hash_ctx->key_dma) {
		EMSG("Fail to get key_dma");
		return TEE_ERROR_GENERIC;
	}

	hash_ctx->iv_dma = virt_to_phys(hash_ctx->iv);
	if (!hash_ctx->iv_dma) {
		EMSG("Fail to get iv_dma");
		return TEE_ERROR_GENERIC;
	}

	hash_ctx->out_dma = virt_to_phys(hash_ctx->out);
	if (!hash_ctx->out_dma) {
		EMSG("Fail to get out_dma");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result hisi_sec_hash_ctx_init(struct hashctx *hash_ctx, uint32_t algo)
{
	TEE_Result ret = TEE_SUCCESS;

	hash_ctx->mac_len = sec_hash_get_mac_len(algo);
	if (!hash_ctx->mac_len) {
		EMSG("Invalid algo type %#"PRIx32, algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	hash_ctx->algo = algo;
	hash_ctx->mode = algo >> HASH_MODE_OFFSET;

	ret = sec_hash_get_dma(hash_ctx);
	if (ret)
		return ret;

	hash_ctx->qp = sec_create_qp(HISI_QM_CHANNEL_TYPE0);
	if (!hash_ctx->qp) {
		EMSG("Fail to create hash qp");
		return TEE_ERROR_BUSY;
	}

	if (hash_ctx->qp->qm->version == HISI_QM_HW_V2) {
		hash_ctx->qp->fill_sqe = sec_digest_fill_sqe;
		hash_ctx->qp->parse_sqe = sec_parse_digest_sqe;
	} else {
		hash_ctx->qp->fill_sqe = sec_digest_fill_bd3_sqe;
		hash_ctx->qp->parse_sqe = sec_parse_digest_bd3_sqe;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_hash_ctx_allocate(struct crypto_hash_ctx **ctx,
					uint32_t algo)
{
	struct crypto_hash *hash = NULL;
	struct hashctx *hash_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!ctx) {
		EMSG("Ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash = calloc(1, sizeof(*hash));
	if (!hash) {
		EMSG("Fail to alloc hash");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	hash_ctx = calloc(1, sizeof(*hash_ctx));
	if (!hash_ctx) {
		EMSG("Fail to alloc hash_ctx");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto free_hash;
	}

	ret = hisi_sec_hash_ctx_init(hash_ctx, algo);
	if (ret)
		goto free_ctx;

	hash->hash_ctx.ops = &hash_ops;
	hash->ctx = hash_ctx;
	*ctx = &hash->hash_ctx;

	return TEE_SUCCESS;

free_ctx:
	free(hash_ctx);
free_hash:
	free(hash);

	return ret;
}

static TEE_Result sec_hash_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_hash(&sec_hash_ctx_allocate);
	if (ret)
		EMSG("Sec hash register to crypto fail ret=%#"PRIx32, ret);

	return ret;
}
driver_init(sec_hash_init);
