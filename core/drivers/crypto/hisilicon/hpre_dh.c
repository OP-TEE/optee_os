// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, HiSilicon Technologies Co., Ltd.
 * Kunpeng hardware accelerator hpre dh algorithm implementation.
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <hpre_dh.h>
#include <hpre_main.h>
#include <initcall.h>
#include <malloc.h>
#include <rng_support.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

static TEE_Result hpre_dh_alloc_keypair(struct dh_keypair *key,
					size_t size_bits)
{
	if (!key || !size_bits) {
		EMSG("Invalid input parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(key, 0, sizeof(*key));
	key->g = crypto_bignum_allocate(size_bits);
	if (!key->g)
		goto g_err;

	key->p = crypto_bignum_allocate(size_bits);
	if (!key->p)
		goto p_err;

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto x_err;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto y_err;

	/* Allocate subprime even if not used */
	key->q = crypto_bignum_allocate(size_bits);
	if (!key->q)
		goto q_err;

	return TEE_SUCCESS;
q_err:
	crypto_bignum_free(&key->y);
y_err:
	crypto_bignum_free(&key->x);
x_err:
	crypto_bignum_free(&key->p);
p_err:
	crypto_bignum_free(&key->g);
g_err:
	EMSG("HPRE dh alloc key pair fail.");

	return TEE_ERROR_OUT_OF_MEMORY;
}

static enum hisi_drv_status hpre_dh_fill_sqe(void *bd, void *info)
{
	struct hpre_dh_msg *msg = info;
	struct hpre_sqe *sqe = bd;

	sqe->w0 = msg->alg_type | SHIFT_U32(0x1, HPRE_DONE_SHIFT);
	sqe->task_len1 = TASK_LENGTH(msg->key_bytes);
	sqe->key = msg->x_p_dma;
	sqe->in = msg->g_dma;
	sqe->out = msg->out_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status hpre_dh_parse_sqe(void *bd, void *info)
{
	struct hpre_dh_msg *msg = info;
	struct hpre_sqe *sqe = bd;
	uint16_t err = 0;
	uint16_t done = 0;

	err = HPRE_TASK_ETYPE(sqe->w0);
	done = HPRE_TASK_DONE(sqe->w0);
	if (done != HPRE_HW_TASK_DONE || err) {
		EMSG("HPRE do dh fail! done=0x%"PRIx16", etype=0x%"PRIx16,
		     done, err);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	if (hpre_bin_to_crypto_bin(msg->out, msg->out, msg->key_bytes,
				   msg->out_bytes)) {
		EMSG("Fail to transfer dh_y from hpre_bin to crypto_bin");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result hpre_dh_do_task(void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	TEE_Result res = TEE_SUCCESS;
	struct hisi_qp *qp = NULL;

	qp = hpre_create_qp(HISI_QM_CHANNEL_TYPE0);
	if (!qp) {
		EMSG("Fail to create dh qp");
		return TEE_ERROR_BUSY;
	}

	qp->fill_sqe = hpre_dh_fill_sqe;
	qp->parse_sqe = hpre_dh_parse_sqe;
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

static size_t round_key_size_to_hw_size(size_t key_bytes)
{
	size_t size = 0;

	if (key_bytes <= 96)
		size = 96;
	else if (key_bytes <= 128)
		size = 128;
	else if (key_bytes <= 192)
		size = 192;
	else if (key_bytes <= 256)
		size = 256;
	else if (key_bytes <= 384)
		size = 384;
	else if (key_bytes <= 512)
		size = 512;
	else
		EMSG("Invalid key_bytes[%zu]", key_bytes);

	return size;
}

static TEE_Result hpre_dh_gen_privkey(struct bignum *x, size_t key_bits)
{
	size_t key_bytes = BITS_TO_BYTES(key_bits);
	uint8_t buf[HPRE_DH_MAX_KEY_BYTES] = { };
	TEE_Result ret = TEE_SUCCESS;

	if (hw_get_random_bytes(buf, key_bytes)) {
		EMSG("Fail to fill privkey");
		return TEE_ERROR_NO_DATA;
	}

	ret = crypto_bignum_bin2bn(buf, key_bytes, x);
	memzero_explicit(buf, key_bytes);

	return ret;
}

static enum hisi_drv_status hpre_dh_params_alloc(struct hpre_dh_msg *msg)
{
	uint32_t size = HPRE_DH_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc dh total buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->x_p = data;
	msg->x_p_dma = virt_to_phys(msg->x_p);

	msg->g = msg->x_p + (msg->key_bytes << 1);
	msg->g_dma = msg->x_p_dma + (msg->key_bytes << 1);
	msg->out = msg->g + msg->key_bytes;
	msg->out_dma = msg->g_dma + msg->key_bytes;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void hpre_dh_params_free(struct hpre_dh_msg *msg)
{
	if (msg->x_p) {
		free_wipe(msg->x_p);
		msg->x_p = NULL;
	}
}

static enum hisi_drv_status hpre_dh_params_bn2bin(struct hpre_dh_msg *msg,
						  struct dh_keypair *key,
						  struct bignum *pubkey)
{
	uint8_t *p = msg->x_p + msg->key_bytes;
	uint8_t *x = msg->x_p;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	msg->xbytes = BITS_TO_BYTES(key->xbits);
	msg->out_bytes = msg->pbytes;
	crypto_bignum_bn2bin(key->x, x);
	crypto_bignum_bn2bin(key->p, p);

	if (!pubkey) {
		msg->gbytes = crypto_bignum_num_bytes(key->g);
		crypto_bignum_bn2bin(key->g, msg->g);
	} else {
		msg->gbytes = crypto_bignum_num_bytes(pubkey);
		if (msg->gbytes != msg->pbytes)
			return HISI_QM_DRVCRYPT_EINVAL;
		crypto_bignum_bn2bin(pubkey, msg->g);
	}

	ret = hpre_bin_from_crypto_bin(x, x, msg->key_bytes, msg->xbytes);
	if (ret) {
		EMSG("Fail to transfer dh_x from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(p, p, msg->key_bytes, msg->pbytes);
	if (ret) {
		EMSG("Fail to transfer dh_p from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(msg->g, msg->g, msg->key_bytes,
				       msg->gbytes);
	if (ret)
		EMSG("Fail to transfer dh_g from crypto_bin to hpre_bin");

	return ret;
}

static TEE_Result hpre_dh_request_init(struct hpre_dh_msg *msg,
				       struct dh_keypair *key,
				       struct bignum *pubkey)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	msg->alg_type = HPRE_ALG_DH;
	msg->key_bytes = round_key_size_to_hw_size(msg->pbytes);
	if (!msg->key_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hpre_dh_params_alloc(msg);
	if (ret)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = hpre_dh_params_bn2bin(msg, key, pubkey);
	if (ret) {
		hpre_dh_params_free(msg);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static void hpre_dh_request_deinit(struct hpre_dh_msg *msg)
{
	hpre_dh_params_free(msg);
}

static TEE_Result hpre_dh_gen_keypair(struct dh_keypair *key,
				      struct bignum *q __unused,
				      size_t key_size)
{
	struct hpre_dh_msg msg = { };
	TEE_Result ret = TEE_SUCCESS;
	size_t p_bits = 0;

	if (!key || !key->g || !key->p || !key->x || !key->y) {
		EMSG("Invalid dh_gen_keypair input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	p_bits = crypto_bignum_num_bits(key->p);
	if (!p_bits) {
		EMSG("p_bits can not be zero");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	msg.pbytes = BITS_TO_BYTES(p_bits);

	if (!key_size) {
		/* xbits */
		key->xbits = p_bits;
		ret = hpre_dh_gen_privkey(key->x, key->xbits);
		if (ret) {
			EMSG("Fail to gen dh privkey");
			return ret;
		}
	} else {
		key->xbits = key_size;
	}

	ret = hpre_dh_request_init(&msg, key, NULL);
	if (ret) {
		EMSG("Fail to init dh msg");
		return ret;
	}

	ret = hpre_dh_do_task(&msg);
	if (ret)
		goto req_deinit;

	ret = crypto_bignum_bin2bn(msg.out, msg.out_bytes, key->y);
	if (ret)
		EMSG("Fail to bin2bn msg out");

req_deinit:
	hpre_dh_request_deinit(&msg);

	return ret;
}

static TEE_Result hpre_dh_do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	struct hpre_dh_msg msg = { };
	struct dh_keypair *key = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!sdata || !sdata->key_priv || !sdata->key_pub) {
		EMSG("Invalid dh_do_shared_secret input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key = sdata->key_priv;
	key->xbits = crypto_bignum_num_bits(key->x);
	if (!key->xbits) {
		EMSG("xbits can not be zero");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	msg.pbytes = crypto_bignum_num_bytes(key->p);

	ret = hpre_dh_request_init(&msg, key, (struct bignum *)sdata->key_pub);
	if (ret) {
		EMSG("Fail to init dh msg");
		return ret;
	}

	ret = hpre_dh_do_task(&msg);
	if (ret)
		goto req_deinit;

	sdata->secret.length = msg.out_bytes;
	memcpy(sdata->secret.data, msg.out, msg.out_bytes);
	memzero_explicit(msg.out, msg.out_bytes);

req_deinit:
	hpre_dh_request_deinit(&msg);

	return ret;
}

static struct drvcrypt_dh driver_dh = {
	.alloc_keypair = hpre_dh_alloc_keypair,
	.gen_keypair = hpre_dh_gen_keypair,
	.shared_secret = hpre_dh_do_shared_secret,
};

TEE_Result hpre_dh_init(void)
{
	TEE_Result ret = drvcrypt_register_dh(&driver_dh);

	if (ret != TEE_SUCCESS)
		EMSG("hpre dh register to crypto fail.");

	return ret;
}

driver_init(hpre_dh_init);
