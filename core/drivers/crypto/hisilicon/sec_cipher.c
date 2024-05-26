// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2024 HiSilicon Limited.
 * Kunpeng hardware accelerator sec cipher algorithm implementation.
 */

#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <initcall.h>
#include <trace.h>
#include <utee_defines.h>

#include "sec_cipher.h"
#include "sec_main.h"

static TEE_Result sec_do_cipher_task(struct hisi_qp *qp, void *msg)
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

static TEE_Result sec_cipher_des_get_c_key_len(size_t key_len,
					       uint8_t *c_key_len)
{
	if (key_len == DES_KEY_SIZE) {
		*c_key_len = CKEY_LEN_DES;
	} else {
		EMSG("Invalid DES key size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_3des_get_c_key_len(size_t key_len,
						uint8_t *c_key_len)
{
	if (key_len == SEC_3DES_2KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_2KEY;
	} else if (key_len == SEC_3DES_3KEY_SIZE) {
		*c_key_len = CKEY_LEN_3DES_3KEY;
	} else {
		EMSG("Invalid 3DES key size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_aes_get_c_key_len(size_t key_len,
					       enum sec_c_mode mode,
					       uint8_t *c_key_len)
{
	switch (mode) {
	case C_MODE_ECB:
	case C_MODE_CBC:
	case C_MODE_CTR:
		switch (key_len) {
		case AES_KEYSIZE_128:
			*c_key_len = CKEY_LEN_128_BIT;
			break;
		case AES_KEYSIZE_192:
			*c_key_len = CKEY_LEN_192_BIT;
			break;
		case AES_KEYSIZE_256:
			*c_key_len = CKEY_LEN_256_BIT;
			break;
		default:
			EMSG("Invalid AES key size");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;
	case C_MODE_XTS:
		switch (key_len) {
		case XTS_KEYSIZE_128:
			*c_key_len = CKEY_LEN_128_BIT;
			break;
		case XTS_KEYSIZE_256:
			*c_key_len = CKEY_LEN_256_BIT;
			break;
		default:
			EMSG("Invalid AES-XTS key size");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;
	default:
		EMSG("Unsupported AES mode");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_sm4_get_c_key_len(size_t key_len,
					       enum sec_c_mode mode,
					       uint8_t *c_key_len)
{
	switch (mode) {
	case C_MODE_ECB:
	case C_MODE_CBC:
	case C_MODE_CTR:
		if (key_len != AES_KEYSIZE_128) {
			EMSG("Invalid SM4 key size");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		*c_key_len = CKEY_LEN_128_BIT;
		break;
	case C_MODE_XTS:
		if (key_len != XTS_KEYSIZE_128) {
			EMSG("Invalid SM4-XTS key size");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		*c_key_len = CKEY_LEN_128_BIT;
		break;
	default:
		EMSG("Unsupported SM4 mode");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_set_key(struct sec_cipher_ctx *c_ctx,
				     uint8_t *key1, size_t key1_len,
				     uint8_t *key2, size_t key2_len)
{
	size_t key_len = key1_len + key2_len;
	TEE_Result ret = TEE_SUCCESS;
	uint8_t c_key_len = 0;

	switch (c_ctx->alg) {
	case C_ALG_DES:
		ret = sec_cipher_des_get_c_key_len(key_len, &c_key_len);
		break;
	case C_ALG_3DES:
		ret = sec_cipher_3des_get_c_key_len(key_len, &c_key_len);
		break;
	case C_ALG_AES:
		ret = sec_cipher_aes_get_c_key_len(key_len, c_ctx->mode,
						   &c_key_len);
		break;
	case C_ALG_SM4:
		ret = sec_cipher_sm4_get_c_key_len(key_len, c_ctx->mode,
						   &c_key_len);
		break;
	default:
		EMSG("Invalid cipher type %#"PRIx8, c_ctx->alg);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	if (ret)
		return ret;

	c_ctx->key_dma = virt_to_phys(c_ctx->key);
	if (!c_ctx->key_dma) {
		EMSG("c_key_dma is NULL");
		return TEE_ERROR_GENERIC;
	}

	c_ctx->key_len = key_len;
	c_ctx->c_key_len = c_key_len;

	memcpy(c_ctx->key, key1, key1_len);
	memcpy(c_ctx->key + key1_len, key2, key2_len);

	return TEE_SUCCESS;
}

static void ctr_iv_inc(uint64_t *ctr, uint32_t inc)
{
	uint64_t v0 = TEE_U64_FROM_BIG_ENDIAN(ctr[0]);
	uint64_t v1 = TEE_U64_FROM_BIG_ENDIAN(ctr[1]);

	/* increment counter (128-bit int) by inc */
	if (ADD_OVERFLOW(v1, inc, &v1))
		v0++;

	ctr[0] = TEE_U64_TO_BIG_ENDIAN(v0);
	ctr[1] = TEE_U64_TO_BIG_ENDIAN(v1);
}

static void xts_multi_galois(unsigned char *data)
{
	int i = 0;
	uint8_t t = 0;
	uint8_t tt = 0;

	for (i = 0; i < AES_SM4_IV_SIZE; i++) {
		tt = data[i] >> LEFT_MOST_BIT;
		data[i] = ((data[i] << 1) | t) & 0xFF;
		t = tt;
	}
	if (tt)
		data[0] ^= 0x87;
}

/*
 * When the IV is delivered by segment,
 * the AES/SM4-ECB is used to update the IV to be used next time.
 */
static TEE_Result xts_iv_update(struct sec_cipher_ctx *c_ctx)
{
	size_t xts_key_len = c_ctx->key_len / 2;
	struct sec_cipher_ctx ecb_ctx = { };
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	ecb_ctx.alg = c_ctx->alg;
	ecb_ctx.mode = C_MODE_ECB;
	ret = sec_cipher_set_key(&ecb_ctx, c_ctx->key + xts_key_len,
				 xts_key_len, NULL, 0);
	if (ret)
		return ret;

	ecb_ctx.encrypt = true;
	ecb_ctx.in = (uint8_t *)c_ctx->iv;
	ecb_ctx.out = (uint8_t *)c_ctx->iv;
	ecb_ctx.in_dma = c_ctx->iv_dma;
	ecb_ctx.out_dma = c_ctx->iv_dma;
	ecb_ctx.len = c_ctx->iv_len;

	ret = sec_do_cipher_task(c_ctx->qp, &ecb_ctx);
	if (ret) {
		EMSG("Fail to encrypt xts iv, ret=%#"PRIx32, ret);
		return ret;
	}

	for (i = 0; i < DIV_ROUND_UP(c_ctx->len, AES_SM4_BLOCK_SIZE); i++)
		xts_multi_galois((uint8_t *)c_ctx->iv);

	ecb_ctx.encrypt = false;
	ret = sec_do_cipher_task(c_ctx->qp, &ecb_ctx);
	if (ret)
		EMSG("Fail to decrypt xts iv, ret=%#"PRIx32, ret);

	return ret;
}

static TEE_Result sec_update_iv(struct sec_cipher_ctx *c_ctx)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t offset = 0;

	switch (c_ctx->mode) {
	case C_MODE_CBC:
		offset = c_ctx->len - c_ctx->iv_len;
		if (c_ctx->encrypt && c_ctx->len >= c_ctx->iv_len)
			memcpy(c_ctx->iv, c_ctx->out + offset, c_ctx->iv_len);
		if (!c_ctx->encrypt && c_ctx->len >= c_ctx->iv_len)
			memcpy(c_ctx->iv, c_ctx->in + offset, c_ctx->iv_len);
		break;
	case C_MODE_CTR:
		/*
		 * Increase the iv counter with the number of processed blocks.
		 */
		ctr_iv_inc(c_ctx->iv, c_ctx->len >> CTR_MODE_LEN_SHIFT);
		break;
	case C_MODE_XTS:
		ret = xts_iv_update(c_ctx);
		break;
	default:
		break;
	}

	return ret;
}

static TEE_Result sec_cipher_iv_check(struct sec_cipher_ctx *c_ctx,
				      size_t iv_size)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	switch (c_ctx->mode) {
	case C_MODE_ECB:
		if (!iv_size)
			ret = TEE_SUCCESS;
		break;
	case C_MODE_CBC:
		if (c_ctx->alg == C_ALG_DES || c_ctx->alg == C_ALG_3DES) {
			if (iv_size == DES_CBC_IV_SIZE)
				ret = TEE_SUCCESS;
			break;
		}
		fallthrough;
	case C_MODE_XTS:
	case C_MODE_CTR:
		if (c_ctx->alg == C_ALG_AES || c_ctx->alg == C_ALG_SM4) {
			if (iv_size == AES_SM4_IV_SIZE)
				ret = TEE_SUCCESS;
		}
		break;
	default:
		break;
	}

	if (ret)
		EMSG("Fail to check iv_size");

	return ret;
}

static TEE_Result sec_cipher_set_iv(struct sec_cipher_ctx *c_ctx,
				    uint8_t *iv, size_t iv_len)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!iv && iv_len) {
		EMSG("iv is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = sec_cipher_iv_check(c_ctx, iv_len);
	if (ret)
		return ret;

	c_ctx->iv_len = iv_len;
	c_ctx->iv_dma = virt_to_phys(c_ctx->iv);
	if (!c_ctx->iv_dma) {
		EMSG("c_iv_dma is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(c_ctx->iv, iv, c_ctx->iv_len);

	return TEE_SUCCESS;
}

static enum hisi_drv_status sec_cipher_bd_fill(void *bd, void *msg)
{
	struct sec_cipher_ctx *c_ctx = msg;
	struct hisi_sec_sqe *sqe = bd;
	uint8_t cipher = 0;
	uint8_t scene = 0;
	uint8_t de = 0;

	sqe->type_auth_cipher = BD_TYPE2;
	scene = SHIFT_U32(SCENE_NOTHING, SEC_SCENE_OFFSET);
	de = SHIFT_U32(DATA_DST_ADDR_ENABLE, SEC_DE_OFFSET);
	sqe->sds_sa_type = de | scene;
	sqe->type2.clen_ivhlen = c_ctx->len;

	sqe->type2.c_alg = c_ctx->alg;
	sqe->type2.icvw_kmode = SHIFT_U32(c_ctx->mode, SEC_CMODE_OFFSET) |
				SHIFT_U32(c_ctx->c_key_len, SEC_CKEY_OFFSET);

	if (c_ctx->encrypt)
		cipher = SHIFT_U32(CIPHER_ENCRYPT, SEC_CIPHER_OFFSET);
	else
		cipher = SHIFT_U32(CIPHER_DECRYPT, SEC_CIPHER_OFFSET);

	sqe->type_auth_cipher |= cipher;

	sqe->type2.data_dst_addr = c_ctx->out_dma;
	sqe->type2.data_src_addr = c_ctx->in_dma;
	sqe->type2.c_key_addr = c_ctx->key_dma;
	sqe->type2.c_ivin_addr = c_ctx->iv_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_cipher_bd_parse(void *bd, void *msg __unused)
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

static enum hisi_drv_status sec_cipher_bd3_fill(void *bd, void *msg)
{
	struct hisi_sec_bd3_sqe *sqe = bd;
	struct sec_cipher_ctx *c_ctx = msg;

	sqe->bd_param = BD_TYPE3 | SHIFT_U32(SCENE_NOTHING,
					     SEC_SCENE_OFFSET_V3) |
			SHIFT_U32(DATA_DST_ADDR_ENABLE, SEC_DE_OFFSET_V3);
	sqe->c_len_ivin = c_ctx->len;
	sqe->c_mode_alg = c_ctx->mode |
			  SHIFT_U32(c_ctx->alg, SEC_CALG_OFFSET_V3);
	sqe->c_icv_key = SHIFT_U32(c_ctx->c_key_len, SEC_CKEY_OFFSET_V3);

	if (c_ctx->encrypt)
		sqe->c_icv_key |= CIPHER_ENCRYPT;
	else
		sqe->c_icv_key |= CIPHER_DECRYPT;

	sqe->data_dst_addr = c_ctx->out_dma;
	sqe->data_src_addr = c_ctx->in_dma;
	sqe->c_key_addr = c_ctx->key_dma;
	sqe->no_scene.c_ivin_addr = c_ctx->iv_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_cipher_bd3_parse(void *bd, void *msg __unused)
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

static TEE_Result cipher_algo_check(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_SM4_CBC_NOPAD:
	case TEE_ALG_SM4_ECB_NOPAD:
	case TEE_ALG_SM4_XTS:
	case TEE_ALG_SM4_CTR:
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result crypto_set_alg(struct sec_cipher_ctx *c_ctx, uint32_t alg)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (alg) {
	case TEE_MAIN_ALGO_DES:
		c_ctx->alg = C_ALG_DES;
		break;
	case TEE_MAIN_ALGO_DES3:
		c_ctx->alg = C_ALG_3DES;
		break;
	case TEE_MAIN_ALGO_AES:
		c_ctx->alg = C_ALG_AES;
		break;
	case TEE_MAIN_ALGO_SM4:
		c_ctx->alg = C_ALG_SM4;
		break;
	default:
		EMSG("Invalid cipher type %#"PRIx32, alg);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	return ret;
}

static TEE_Result crypto_set_mode(struct sec_cipher_ctx *c_ctx, uint32_t mode)
{
	TEE_Result ret = TEE_SUCCESS;

	switch (mode) {
	case TEE_CHAIN_MODE_ECB_NOPAD:
		c_ctx->mode = C_MODE_ECB;
		break;
	case TEE_CHAIN_MODE_CBC_NOPAD:
		c_ctx->mode = C_MODE_CBC;
		break;
	case TEE_CHAIN_MODE_XTS:
		c_ctx->mode = C_MODE_XTS;
		break;
	case TEE_CHAIN_MODE_CTR:
		c_ctx->mode = C_MODE_CTR;
		break;
	default:
		EMSG("Invalid cipher mode type %#"PRIx32, mode);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	return ret;
}

static TEE_Result sec_cipher_ctx_allocate(void **ctx, uint32_t algo)
{
	struct sec_cipher_ctx *c_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!ctx) {
		EMSG("ctx is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = cipher_algo_check(algo);
	if (ret)
		return ret;

	c_ctx = calloc(1, sizeof(struct sec_cipher_ctx));
	if (!c_ctx) {
		EMSG("c_ctx is NULL");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ret = crypto_set_alg(c_ctx, TEE_ALG_GET_MAIN_ALG(algo));
	if (ret)
		goto free_c_ctx;

	ret = crypto_set_mode(c_ctx, TEE_ALG_GET_CHAIN_MODE(algo));
	if (ret)
		goto free_c_ctx;

	c_ctx->qp = sec_create_qp(HISI_QM_CHANNEL_TYPE0);
	if (!c_ctx->qp) {
		ret = TEE_ERROR_BUSY;
		goto free_c_ctx;
	}

	if (c_ctx->qp->qm->version == HISI_QM_HW_V2) {
		c_ctx->qp->fill_sqe = sec_cipher_bd_fill;
		c_ctx->qp->parse_sqe = sec_cipher_bd_parse;
	} else {
		c_ctx->qp->fill_sqe = sec_cipher_bd3_fill;
		c_ctx->qp->parse_sqe = sec_cipher_bd3_parse;
	}

	c_ctx->offs = 0;
	*ctx = c_ctx;

	return TEE_SUCCESS;

free_c_ctx:
	free(c_ctx);

	return ret;
}

static void sec_cipher_ctx_free(void *ctx)
{
	struct sec_cipher_ctx *c_ctx = ctx;

	if (!c_ctx)
		return;

	hisi_qm_release_qp(c_ctx->qp);
	memzero_explicit(c_ctx->key, c_ctx->key_len);
	free(c_ctx);
}

static TEE_Result sec_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	struct sec_cipher_ctx *c_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!dinit || !dinit->ctx || !dinit->key1.data) {
		EMSG("drvcrypt_cipher init param error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	c_ctx = dinit->ctx;

	ret = sec_cipher_set_key(c_ctx, dinit->key1.data, dinit->key1.length,
				 dinit->key2.data, dinit->key2.length);
	if (ret)
		return ret;

	ret = sec_cipher_set_iv(c_ctx, dinit->iv.data, dinit->iv.length);
	if (ret)
		return ret;

	c_ctx->encrypt = dinit->encrypt;

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_cryptlen_check(struct sec_cipher_ctx *c_ctx,
					    size_t length)
{
	if (c_ctx->mode == C_MODE_XTS && length < AES_SM4_BLOCK_SIZE) {
		EMSG("Invalid xts src len");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((c_ctx->mode == C_MODE_ECB || c_ctx->mode == C_MODE_CBC) &&
	    (length & (AES_SM4_BLOCK_SIZE - 1))) {
		EMSG("Invalid ecb cbc src len");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_param_check(struct drvcrypt_cipher_update *dupdate)
{
	struct sec_cipher_ctx *c_ctx = NULL;

	if (!dupdate || !dupdate->src.data || !dupdate->dst.data ||
	    dupdate->src.length != dupdate->dst.length ||
	    dupdate->src.length > MAX_CIPHER_LENGTH || !dupdate->src.length) {
		EMSG("Dupdate input param error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	c_ctx = dupdate->ctx;
	switch (c_ctx->alg) {
	case C_ALG_SM4:
	case C_ALG_AES:
		if (sec_cipher_cryptlen_check(c_ctx, dupdate->src.length))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case C_ALG_DES:
	case C_ALG_3DES:
		if (dupdate->src.length % TEE_DES_BLOCK_SIZE) {
			EMSG("Invalid src len");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_alloc_buffer(struct sec_cipher_ctx *c_ctx)
{
	c_ctx->in = malloc(c_ctx->len);
	if (!c_ctx->in) {
		EMSG("Fail to alloc c_in buf");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	c_ctx->in_dma = virt_to_phys(c_ctx->in);

	c_ctx->out = malloc(c_ctx->len);
	if (!c_ctx->out) {
		EMSG("Fail to alloc c_out buf");
		goto free_c_in;
	}

	c_ctx->out_dma = virt_to_phys(c_ctx->out);

	return TEE_SUCCESS;

free_c_in:
	free(c_ctx->in);
	c_ctx->in = NULL;
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void sec_free_buffer(struct sec_cipher_ctx *c_ctx)
{
	free(c_ctx->in);
	free(c_ctx->out);
	c_ctx->in = NULL;
	c_ctx->out = NULL;
}

static TEE_Result sec_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	struct sec_cipher_ctx *c_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;
	size_t padding_size = 0;

	ret = sec_cipher_param_check(dupdate);
	if (ret)
		return ret;

	c_ctx = dupdate->ctx;
	if (c_ctx->mode == C_MODE_CTR && (c_ctx->offs & CTR_SRC_ALIGN_MASK))
		padding_size = c_ctx->offs % CTR_SRC_BLOCK_SIZE;

	c_ctx->offs += dupdate->src.length;
	c_ctx->len = dupdate->src.length + padding_size;
	ret = sec_alloc_buffer(c_ctx);
	if (ret)
		return ret;

	memset(c_ctx->in, 0, padding_size);
	memcpy(c_ctx->in + padding_size, dupdate->src.data,
	       dupdate->src.length);

	ret = sec_do_cipher_task(c_ctx->qp, c_ctx);
	if (ret)
		goto free_buffer;

	ret = sec_update_iv(c_ctx);
	if (ret) {
		EMSG("Fail to update iv, ret=%#"PRIx32, ret);
		goto free_buffer;
	}

	memcpy(dupdate->dst.data, c_ctx->out + padding_size,
	       dupdate->src.length);

free_buffer:
	sec_free_buffer(c_ctx);
	return ret;
}

static void sec_cipher_final(void *ctx __unused)
{
}

static void sec_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct sec_cipher_ctx *dst_c_ctx = dst_ctx;
	struct sec_cipher_ctx *src_c_ctx = src_ctx;

	dst_c_ctx->alg = src_c_ctx->alg;
	dst_c_ctx->mode = src_c_ctx->mode;
	dst_c_ctx->encrypt = src_c_ctx->encrypt;
	dst_c_ctx->offs = src_c_ctx->offs;

	if (src_c_ctx->key_len) {
		dst_c_ctx->key_len = src_c_ctx->key_len;
		dst_c_ctx->c_key_len = src_c_ctx->c_key_len;
		memcpy(dst_c_ctx->key, src_c_ctx->key, dst_c_ctx->key_len);
		dst_c_ctx->key_dma = virt_to_phys(dst_c_ctx->key);
	} else {
		dst_c_ctx->key_len = 0;
		dst_c_ctx->c_key_len = 0;
	}

	if (src_c_ctx->iv_len) {
		dst_c_ctx->iv_len = src_c_ctx->iv_len;
		memcpy(dst_c_ctx->iv, src_c_ctx->iv, dst_c_ctx->iv_len);
		dst_c_ctx->iv_dma = virt_to_phys(dst_c_ctx->iv);
	} else {
		dst_c_ctx->iv_len = 0;
	}
}

static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = sec_cipher_ctx_allocate,
	.free_ctx = sec_cipher_ctx_free,
	.init = sec_cipher_initialize,
	.update = sec_cipher_update,
	.final = sec_cipher_final,
	.copy_state = sec_cipher_copy_state,
};

static TEE_Result sec_cipher_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_cipher(&driver_cipher);
	if (ret)
		EMSG("Sec cipher register to crypto fail ret=%#"PRIx32, ret);

	return ret;
}
driver_init(sec_cipher_init);
