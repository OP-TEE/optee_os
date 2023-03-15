// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, HiSilicon Limited
 */
#include "hisi_sec.h"
#include "sec_cipher.h"

static TEE_Result sec_do_cipher_task(struct hisi_qp *qp, void *msg)
{
	int32_t ret;

	ret = hisi_qp_send(qp, msg);
	if (ret) {
		EMSG("Fail to send task, ret=%d!\n", ret);
		return TEE_ERROR_BAD_STATE;
	}

	ret = hisi_qp_recv_sync(qp, msg);
	if (ret) {
		EMSG("Recv task error, ret=%d!\n", ret);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

/* increment counter (128-bit int) by c */
static void ctr_iv_inc(uint8_t *counter, uint32_t shift_len)
{
	uint32_t n = CTR_128BIT_COUNTER;
	uint8_t *counter1 = counter;
	uint32_t c = shift_len;

	do {
		--n;
		c += counter1[n];
		counter1[n] = (uint8_t)c;
		c >>= BYTE_BITS;
	} while (n);
}

static void xts_multi_galois(unsigned char *data)
{
	int i;
	uint8_t t, tt;

	for (i = 0, t = 0; i < AES_SM4_IV_SIZE; i++) {
		tt = data[i] >> LEFT_MOST_BIT;
		data[i] = ((data[i] << 1) | t) & 0xFF;
		t = tt;
	}
	if (tt)
		data[0] ^= 0x87;
}

static int sec_cipher_set_key(struct sec_cipher_ctx *c_ctx,
			      const uint8_t *key1, const int key1_len,
			      const uint8_t *key2, const int key2_len);

/* When the IV is delivered by segment, the AES/SM4-ECB is used
 * to update the IV to be used next time.
 */
static uint32_t xts_iv_update(struct sec_cipher_ctx *c_ctx)
{
	size_t i = 0;
	uint32_t ret = 0;
	size_t xts_key_len = c_ctx->key_len / 2;
	struct sec_cipher_ctx ecb_ctx = {0};

	ecb_ctx.alg = c_ctx->alg;
	ecb_ctx.mode = C_MODE_ECB;
	ret = sec_cipher_set_key(&ecb_ctx, c_ctx->key + xts_key_len,
				 xts_key_len, NULL, 0);
	if (ret)
		return ret;

	ecb_ctx.encrypt = true;
	ecb_ctx.in = c_ctx->iv;
	ecb_ctx.out = c_ctx->iv;
	ecb_ctx.in_dma = c_ctx->iv_dma;
	ecb_ctx.out_dma = c_ctx->iv_dma;
	ecb_ctx.len = c_ctx->iv_len;

	ret = sec_do_cipher_task(c_ctx->qp, &ecb_ctx);
	if (ret != 0) {
		EMSG("Xts iv enc failed . ret = %x.\n", ret);
		return ret;
	}

	for (i = 0; i < MULTIPLE_ROUND(c_ctx->len, AES_SM4_BLOCK_SIZE); i++)
		xts_multi_galois(c_ctx->iv);

	ecb_ctx.encrypt = false;
	ret = sec_do_cipher_task(c_ctx->qp, &ecb_ctx);
	if (ret != 0)
		EMSG("Xts iv denc failed . ret = %x.\n", ret);

	return ret;
}

static uint32_t sec_update_iv(struct sec_cipher_ctx *c_ctx)
{
	uint32_t ret = 0;
	size_t offset;

	switch (c_ctx->mode) {
	case C_MODE_CBC:
		offset = c_ctx->len - c_ctx->iv_len;
		if (c_ctx->encrypt && c_ctx->len >= c_ctx->iv_len)
			memcpy(c_ctx->iv, c_ctx->out + offset, c_ctx->iv_len);
		if (!c_ctx->encrypt && c_ctx->len >= c_ctx->iv_len)
			memcpy(c_ctx->iv, c_ctx->in + offset, c_ctx->iv_len);
		break;
	case C_MODE_CTR:
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

static int sec_cipher_des_get_c_key_len(const int key_len, uint8_t *c_key_len)
{
	if (key_len == DES_KEY_SIZE)
		*c_key_len = CKEY_LEN_DES;
	else {
		EMSG("Invalid DES key size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static int sec_cipher_3des_get_c_key_len(const int key_len, uint8_t *c_key_len)
{
	if (key_len == SEC_3DES_2KEY_SIZE)
		*c_key_len = CKEY_LEN_3DES_2KEY;
	else if (key_len == SEC_3DES_3KEY_SIZE)
		*c_key_len = CKEY_LEN_3DES_3KEY;
	else {
		EMSG("Invalid 3DES key size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static int sec_cipher_aes_get_c_key_len(const int key_len,
					const uint8_t mode, uint8_t *c_key_len)
{
	switch (mode) {
	case C_MODE_ECB:
	case C_MODE_CBC:
	case C_MODE_CTR:
	case C_MODE_GCM:
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
		EMSG("Unsupport AES mode\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static int sec_cipher_sm4_get_c_key_len(const int key_len, const uint8_t mode,
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
		EMSG("Unsupport SM4 mode\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static int sec_cipher_set_key(struct sec_cipher_ctx *c_ctx,
			      const uint8_t *key1, const int key1_len,
			      const uint8_t *key2, const int key2_len)
{
	int key_len = key1_len + key2_len;
	uint8_t c_key_len;
	int ret;

	switch (c_ctx->alg) {
	case C_ALG_DES:
		ret = sec_cipher_des_get_c_key_len(key_len, &c_key_len);
		break;
	case C_ALG_3DES:
		ret = sec_cipher_3des_get_c_key_len(key_len, &c_key_len);
		break;
	case C_ALG_AES:
		ret = sec_cipher_aes_get_c_key_len(key_len,
						   c_ctx->mode, &c_key_len);
		break;
	case C_ALG_SM4:
		ret = sec_cipher_sm4_get_c_key_len(key_len,
						   c_ctx->mode, &c_key_len);
		break;
	default:
		EMSG("Invalid cipher type! %x\n", c_ctx->alg);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	if (ret)
		return ret;

	c_ctx->key_dma = virt_to_phys(c_ctx->key);
	assert(c_ctx->key_dma);

	c_ctx->key_len = key_len;
	c_ctx->c_key_len = c_key_len;

	memcpy(c_ctx->key, key1, key1_len);
	memcpy(c_ctx->key + key1_len, key2, key2_len);

	return ret;
}

static int sec_cipher_iv_check(struct sec_cipher_ctx *c_ctx, const int iv_size)
{
	int ret;

	switch (c_ctx->mode) {
	case C_MODE_ECB:
		ret = iv_size == 0 ? 0 : TEE_ERROR_BAD_PARAMETERS;
		break;
	case C_MODE_CBC:
		if (c_ctx->alg == C_ALG_DES || c_ctx->alg == C_ALG_3DES) {
			ret = iv_size == DES_CBC_IV_SIZE ?
				0 : TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		fallthrough;
	case C_MODE_XTS:
	case C_MODE_CTR:
		if (c_ctx->alg == C_ALG_AES || c_ctx->alg == C_ALG_SM4) {
			ret = iv_size == AES_SM4_IV_SIZE ?
				0 : TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		fallthrough;
	default:
		ret = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	if (ret)
		EMSG("iv_size check failed.\n");

	return ret;
}

static int sec_cipher_set_iv(struct sec_cipher_ctx *c_ctx, const uint8_t *iv,
			     const int iv_len)
{
	int ret;

	if (!iv && iv_len != 0) {
		EMSG("Iv is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = sec_cipher_iv_check(c_ctx, iv_len);
	if (ret)
		return ret;

	c_ctx->iv_len = iv_len;
	c_ctx->iv_dma = virt_to_phys(c_ctx->iv);
	assert(c_ctx->iv_dma);

	memcpy(c_ctx->iv, iv, c_ctx->iv_len);

	return TEE_SUCCESS;
}

static int32_t sec_cipher_bd_fill(void *bd, void *msg)
{
	struct sec_cipher_ctx *c_ctx = (struct sec_cipher_ctx *)msg;
	struct hisi_sec_sqe *sqe = (struct hisi_sec_sqe *)bd;

	sqe->type = BD_TYPE2;
	sqe->scene = SCENE_IPSEC;
	sqe->de = DATA_DST_ADDR_ENABLE;
	sqe->type2.c_len = c_ctx->len;
	sqe->src_addr_type = HISI_FLAT_BUF;
	sqe->dst_addr_type = HISI_FLAT_BUF;
	sqe->type2.c_alg = c_ctx->alg;
	sqe->type2.c_mode = c_ctx->mode;
	sqe->type2.c_key_len = c_ctx->c_key_len;

	if (c_ctx->encrypt)
		sqe->cipher = CIPHER_ENCRYPT;
	else
		sqe->cipher = CIPHER_DECRYPT;

	sqe->type2.data_dst_addr_l = lower_32_bits(c_ctx->out_dma);
	sqe->type2.data_dst_addr_h = upper_32_bits(c_ctx->out_dma);
	sqe->type2.data_src_addr_l = lower_32_bits(c_ctx->in_dma);
	sqe->type2.data_src_addr_h = upper_32_bits(c_ctx->in_dma);
	sqe->type2.c_key_addr_l = lower_32_bits(c_ctx->key_dma);
	sqe->type2.c_key_addr_h = upper_32_bits(c_ctx->key_dma);

	if (c_ctx->iv_len == 0)
		return TEE_SUCCESS;

	sqe->type2.c_ivin_addr_l = lower_32_bits(c_ctx->iv_dma);
	sqe->type2.c_ivin_addr_h = upper_32_bits(c_ctx->iv_dma);

	return TEE_SUCCESS;
}

static int32_t sec_cipher_bd_parse(void *bd, void *msg __unused)
{
	struct hisi_sec_sqe *sqe = (struct hisi_sec_sqe *)bd;

	if (sqe->type2.done != SEC_HW_TASK_DONE || sqe->type2.error_type) {
		EMSG("SEC BD2 fail! done=0x%x, etype=0x%x\n",
		     sqe->type2.done, sqe->type2.error_type);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static int32_t sec_cipher_bd3_fill(void *bd, void *msg)
{
	struct hisi_sec_bd3_sqe *sqe = (struct hisi_sec_bd3_sqe *)bd;
	struct sec_cipher_ctx *c_ctx = (struct sec_cipher_ctx *)msg;

	sqe->type = BD_TYPE3;
	sqe->scene = SCENE_IPSEC;
	sqe->de = DATA_DST_ADDR_ENABLE;
	sqe->c_len = c_ctx->len;
	sqe->src_addr_type = HISI_FLAT_BUF;
	sqe->dst_addr_type = HISI_FLAT_BUF;
	sqe->c_alg = c_ctx->alg;
	sqe->c_mode = c_ctx->mode;
	sqe->c_key_len = c_ctx->c_key_len;

	if (c_ctx->encrypt)
		sqe->cipher = CIPHER_ENCRYPT;
	else
		sqe->cipher = CIPHER_DECRYPT;

	sqe->data_dst_addr_l = lower_32_bits(c_ctx->out_dma);
	sqe->data_dst_addr_h = upper_32_bits(c_ctx->out_dma);
	sqe->data_src_addr_l = lower_32_bits(c_ctx->in_dma);
	sqe->data_src_addr_h = upper_32_bits(c_ctx->in_dma);
	sqe->c_key_addr_l = lower_32_bits(c_ctx->key_dma);
	sqe->c_key_addr_h = upper_32_bits(c_ctx->key_dma);

	if (c_ctx->iv_len == 0)
		return TEE_SUCCESS;

	sqe->ipsec_scene.c_ivin_addr_l = lower_32_bits(c_ctx->iv_dma);
	sqe->ipsec_scene.c_ivin_addr_h = upper_32_bits(c_ctx->iv_dma);
	return TEE_SUCCESS;
}

static int32_t sec_cipher_bd3_parse(void *bd, void *msg __unused)
{
	struct hisi_sec_bd3_sqe *sqe = (struct hisi_sec_bd3_sqe *)bd;

	if (sqe->done != SEC_HW_TASK_DONE || sqe->error_type) {
		EMSG("SEC BD3 fail! done=0x%x, etype=0x%x\n",
		     sqe->done, sqe->error_type);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
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
	case TEE_ALG_SM4_CTR:
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;
}

static int crypto_set_calg(struct sec_cipher_ctx *c_ctx, const uint32_t alg)
{
	int ret = TEE_SUCCESS;

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
		EMSG("Invalid cipher type! %x\n", alg);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	return ret;
}

static int crypto_set_cmode(struct sec_cipher_ctx *c_ctx, const uint32_t mode)
{
	int ret = TEE_SUCCESS;

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
		EMSG("Invalid cipher mode type! %x\n", mode);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	}

	return ret;
}

static TEE_Result sec_cipher_ctx_allocate(void **ctx, uint32_t algo)
{
	struct sec_cipher_ctx *c_ctx;
	int ret;

	if (!ctx) {
		EMSG("Ctx is NULL");
		return TEE_ERROR_STORAGE_NO_SPACE;
	}

	ret = cipher_algo_check(algo);
	if (ret != 0)
		return ret;

	c_ctx = (struct sec_cipher_ctx *)malloc(sizeof(struct sec_cipher_ctx));
	if (!c_ctx) {
		EMSG("c_ctx is NULL");
		return TEE_ERROR_STORAGE_NO_SPACE;
	}

	ret = crypto_set_calg(c_ctx, TEE_ALG_GET_MAIN_ALG(algo));
	if (ret)
		goto free_c_ctx;

	ret = crypto_set_cmode(c_ctx, TEE_ALG_GET_CHAIN_MODE(algo));
	if (ret)
		goto free_c_ctx;

	c_ctx->qp = sec_create_qp(QM_CHANNEL_TYPE0);
	if (!c_ctx->qp) {
		ret = TEE_ERROR_BUSY;
		goto free_c_ctx;
	}

	if (c_ctx->qp->qm->version == QM_HW_V2) {
		c_ctx->qp->fill_sqe = sec_cipher_bd_fill;
		c_ctx->qp->parse_sqe = sec_cipher_bd_parse;
	} else {
		c_ctx->qp->fill_sqe = sec_cipher_bd3_fill;
		c_ctx->qp->parse_sqe = sec_cipher_bd3_parse;
	}

	c_ctx->offs = 0;
	(*ctx) = c_ctx;

	return TEE_SUCCESS;

free_c_ctx:
	free(c_ctx);

	return ret;
}

static void sec_cipher_ctx_free(void *ctx)
{
	struct sec_cipher_ctx *c_ctx = (struct sec_cipher_ctx *)ctx;

	if (!c_ctx)
		return;

	hisi_qm_release_qp(c_ctx->qp);
	memset(c_ctx->key, 0, c_ctx->key_len);
	free(c_ctx);

	IMSG("Cipher free ctx done!");
}

static TEE_Result sec_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	struct sec_cipher_ctx *c_ctx;
	TEE_Result ret;

	if (!dinit || !dinit->ctx || !dinit->key1.data) {
		EMSG("drvcrypt_cipher init param error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	c_ctx = (struct sec_cipher_ctx *)dinit->ctx;

	ret = sec_cipher_set_key(c_ctx, dinit->key1.data, dinit->key1.length,
				 dinit->key2.data, dinit->key2.length);
	if (ret != 0)
		return ret;

	ret = sec_cipher_set_iv(c_ctx, dinit->iv.data, dinit->iv.length);
	if (ret != 0)
		return ret;

	c_ctx->encrypt = dinit->encrypt;

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_cryptlen_check(struct sec_cipher_ctx *c_ctx,
					    size_t length)
{
	if (c_ctx->mode == C_MODE_XTS && length < AES_SM4_BLOCK_SIZE) {
		EMSG("Invalid src len");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if ((c_ctx->mode == C_MODE_ECB || c_ctx->mode == C_MODE_CBC) &&
	    (length & (AES_SM4_BLOCK_SIZE - 1)) != 0) {
		EMSG("Invalid src len");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result sec_cipher_param_check(struct drvcrypt_cipher_update *dupdate)
{
	struct sec_cipher_ctx *c_ctx;

	if (!dupdate || !dupdate->src.data || !dupdate->dst.data ||
	    dupdate->src.length != dupdate->dst.length ||
	    dupdate->src.length > MAX_CIPHER_LENGTH ||
	    !dupdate->src.length) {
		EMSG("Dupdate input param error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	c_ctx = (struct sec_cipher_ctx *)dupdate->ctx;
	switch (c_ctx->alg) {
	case C_ALG_SM4:
	case C_ALG_AES:
		if (sec_cipher_cryptlen_check(c_ctx, dupdate->src.length) != 0)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case C_ALG_DES:
	case C_ALG_3DES:
		if (dupdate->src.length % TEE_DES_BLOCK_SIZE != 0) {
			EMSG("Invalid src len");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static int sec_alloc_buffer(struct sec_cipher_ctx *c_ctx)
{
	c_ctx->in = (uint8_t *)malloc(c_ctx->len);
	if (!c_ctx->in) {
		EMSG("Failed to alloc c_in buf.\n");
		return TEE_ERROR_STORAGE_NO_SPACE;
	}

	c_ctx->in_dma = virt_to_phys(c_ctx->in);
	assert(c_ctx->in_dma);

	c_ctx->out = (uint8_t *)malloc(c_ctx->len);
	if (!c_ctx->out) {
		EMSG("Failed to alloc c_out buf.\n");
		goto free_c_in;
	}

	c_ctx->out_dma = virt_to_phys(c_ctx->out);
	assert(c_ctx->out_dma);

	return TEE_SUCCESS;

free_c_out:
	free(c_ctx->out);
free_c_in:
	free(c_ctx->in);
	return TEE_ERROR_STORAGE_NO_SPACE;
}

static void sec_free_buffer(struct sec_cipher_ctx *c_ctx)
{
	free(c_ctx->in);
	free(c_ctx->out);
}

static TEE_Result sec_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	struct sec_cipher_ctx *c_ctx = NULL;
	size_t padding_size = 0;
	TEE_Result ret;

	ret = sec_cipher_param_check(dupdate);
	if (ret != 0)
		return ret;

	c_ctx = (struct sec_cipher_ctx *)dupdate->ctx;
	if (c_ctx->mode == C_MODE_CTR && (c_ctx->offs & CTR_SRC_ALIGN_MASK))
		padding_size = (c_ctx->offs % CTR_SRC_BLOCK_SIZE);

	c_ctx->offs += dupdate->src.length;
	c_ctx->len = dupdate->src.length + padding_size;
	ret = sec_alloc_buffer(c_ctx);
	if (ret)
		return ret;

	memset(c_ctx->in, 0, padding_size);
	memcpy(c_ctx->in + padding_size,
	       dupdate->src.data, dupdate->src.length);

	ret = sec_do_cipher_task(c_ctx->qp, c_ctx);
	if (ret != 0)
		goto free_buffer;

	ret = sec_update_iv(c_ctx);
	if (ret != 0) {
		EMSG("sec_update_iv failed. ret = %x.\n", ret);
		goto free_buffer;
	}

	memcpy(dupdate->dst.data,
	       c_ctx->out + padding_size, dupdate->src.length);

free_buffer:
	sec_free_buffer(c_ctx);
	return ret;
}

/*
 * Finalize of the cipher operation
 *
 * @ctx	Caller context variable or NULL
 */
static void sec_cipher_final(void *ctx __unused)
{
}

static void sec_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct sec_cipher_ctx *dst_c_ctx = (struct sec_cipher_ctx *)dst_ctx;
	struct sec_cipher_ctx *src_c_ctx = (struct sec_cipher_ctx *)src_ctx;

	dst_c_ctx->alg = src_c_ctx->alg;
	dst_c_ctx->mode = src_c_ctx->mode;
	dst_c_ctx->encrypt = src_c_ctx->encrypt;
	dst_c_ctx->offs = src_c_ctx->offs;

	if (src_c_ctx->key_len) {
		dst_c_ctx->key_len = src_c_ctx->key_len;
		dst_c_ctx->c_key_len = src_c_ctx->c_key_len;
		memcpy(dst_c_ctx->key, src_c_ctx->key, dst_c_ctx->key_len);
		dst_c_ctx->key_dma = virt_to_phys(dst_c_ctx->key);
		assert(dst_c_ctx->key_dma);
	}

	if (src_c_ctx->iv_len) {
		dst_c_ctx->iv_len = src_c_ctx->iv_len;
		memcpy(dst_c_ctx->iv, src_c_ctx->iv, dst_c_ctx->iv_len);
		dst_c_ctx->iv_dma = virt_to_phys(dst_c_ctx->iv);
		assert(dst_c_ctx->iv_dma);
	}
}

/*
 * Registration of the Cipher Driver
 */
static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = sec_cipher_ctx_allocate,
	.free_ctx = sec_cipher_ctx_free,
	.init = sec_cipher_initialize,
	.update = sec_cipher_update,
	.final = sec_cipher_final,
	.copy_state = sec_cipher_copy_state,
};

/*
 * Initialize the Cipher module
 *
 */
static TEE_Result sec_cipher_init(void)
{
	TEE_Result ret = drvcrypt_register_cipher(&driver_cipher);

	if (ret != TEE_SUCCESS)
		EMSG("Sec cipher register failed. ret = 0x%x.\n", ret);

	return ret;
}
driver_init(sec_cipher_init);
