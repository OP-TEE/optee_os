// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, HiSilicon Technologies Co., Ltd.
 * Kunpeng hardware accelerator hpre montgomery algorithm implementation.
 */
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <initcall.h>
#include <malloc.h>
#include <rng_support.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#include "hpre_main.h"
#include "hpre_montgomery.h"

#define X25519_CURVE_INDEX 0
#define X448_CURVE_INDEX 1

struct hpre_mgm_curve {
	uint32_t key_bits;
	const uint8_t *p;
	const uint8_t *a;
	const uint8_t *x;
};

/* NID_X25519 */
/* p = (2 ^ 255 - 19) big endian */
static const uint8_t g_x25519_p[] = {
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

/* a = (486662 - 2) / 4  = 121665 big endian */
static const uint8_t g_x25519_a[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xDB, 0x41
};

/* big endian */
static const uint8_t g_x25519_gx[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09
};

/* NID_X448 */
/* p = (2 ^ 448 - 2 ^ 224 - 1) big endian */
static const uint8_t g_x448_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* a = (156326 - 2) / 4  = 39081 big endian */
static const uint8_t g_x448_a[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0xA9
};

/* big endian */
static const uint8_t g_x448_gx[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
};

static const struct hpre_mgm_curve g_curve_list[] = {
	{
		.key_bits = 256,
		.p = g_x25519_p,
		.a = g_x25519_a,
		.x = g_x25519_gx,
	}, {
		.key_bits = 448,
		.p = g_x448_p,
		.a = g_x448_a,
		.x = g_x448_gx,
	}
};

static TEE_Result
hpre_montgomery_alloc_keypair(struct montgomery_keypair *key,
			      size_t size_bits)
{
	size_t key_size = BITS_TO_BYTES(size_bits);

	if (!key || (size_bits != X25519_KEY_BITS &&
		     size_bits != X448_KEY_BITS)) {
		EMSG("Invalid input parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key->priv = calloc(1, key_size);
	if (!key->priv)
		goto priv_err;

	key->pub = calloc(1, key_size);
	if (!key->pub)
		goto pub_err;

	return TEE_SUCCESS;
pub_err:
	free(key->priv);
	key->priv = NULL;
priv_err:
	EMSG("HPRE montgomery alloc key pair fail");

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result gen_random_privkey(uint8_t *priv, size_t key_bits)
{
	size_t key_size = BITS_TO_BYTES(key_bits);
	TEE_Result ret = TEE_SUCCESS;

	if (!priv) {
		EMSG("Privkey param is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = hw_get_random_bytes(priv, key_size);
	if (ret) {
		EMSG("Fail to fill privkey");
		return TEE_ERROR_NO_DATA;
	}

	return ret;
}

static enum hisi_drv_status
hpre_montgomery_params_alloc(struct hpre_montgomery_msg *msg)
{
	uint32_t size = HPRE_MONTGOMERY_TOTAL_BUF_SIZE(msg->key_bytes);

	msg->key = calloc(1, size);
	if (!msg->key) {
		EMSG("Fail to alloc montgomery key buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->key_dma = virt_to_phys(msg->key);
	msg->in = msg->key + HPRE_X_KEY_SIZE(msg->key_bytes);
	msg->in_dma = msg->key_dma + HPRE_X_KEY_SIZE(msg->key_bytes);
	msg->out = msg->in + msg->key_bytes;
	msg->out_dma = msg->in_dma + msg->key_bytes;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void hpre_montgomery_params_free(struct hpre_montgomery_msg *msg)
{
	if (msg->key) {
		memzero_explicit(msg->key, HPRE_X_KEY_SIZE(msg->key_bytes));
		free(msg->key);
		msg->key = NULL;
	}
}

static enum hisi_drv_status
hpre_montgomery_params_pretreatment(struct hpre_montgomery_msg *msg)
{
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *k = a + msg->key_bytes;
	uint8_t *u = msg->in;
	uint8_t *dst = k;
	uint32_t bsize = msg->key_bytes;
	uint32_t dsize = msg->curve_bytes;
	/*
	 * It is a constraint of HPRE hardware that key_bytes will be set
	 * to 72 when curve_bytes is between 48 and 72, and the high-order
	 * bits will be set to 0.
	 */
	uint32_t offset = bsize - dsize;
	int ret = 0;

	/*
	 * This is a pretreatment of X25519 with a 32-byte integer,
	 * as described in RFC 7748:
	 * Set the three LSB of the first byte and MSB of the last
	 * to zero, set the second MSB of the last byte to 1.
	 * When receiving u-array, set MSB of last byte to zero.
	 * HPRE hardware module uses big-endian mode, so the bytes to be
	 * set are reversed compared to RFC 7748
	 */
	if (msg->key_bytes == BITS_TO_BYTES(X25519_KEY_BITS)) {
		dst[31] &= 0xF8;
		dst[0] &= 0x7F;
		dst[0] |= 0x40;
		u[0] &= 0x7F;
	} else {
		/*
		 * This is a pretreatment of X448 with a 56-byte integer,
		 * as described in RFC 7748:
		 * For X448, set the two LSB of the first byte to 0, and MSB of the
		 * last byte to 1.
		 * HPRE hardware module uses big-endian mode, so the bytes to be
		 * set are reversed compared to RFC 7748
		 */
		dst[55 + offset] &= 0xFC;
		dst[0 + offset] |= 0x80;
	}

	ret = memcmp(u + offset, p + offset, dsize);
	if (ret >= 0) {
		EMSG("u >= p");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status
hpre_montgomery_params_fill(const struct hpre_mgm_curve *curve,
			    struct hpre_montgomery_msg *msg,
			    uint8_t *privkey, uint8_t *pubkey)
{
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *k = a + msg->key_bytes;
	uint8_t *x = msg->in;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	memcpy(p, curve->p, msg->curve_bytes);
	memcpy(a, curve->a, msg->curve_bytes);
	memcpy(k, privkey, msg->curve_bytes);
	msg->x_bytes = msg->curve_bytes;
	if (!pubkey)
		memcpy(x, curve->x, msg->x_bytes);
	else
		memcpy(x, pubkey, msg->x_bytes);

	ret = hpre_bin_from_crypto_bin(p, p, msg->key_bytes, msg->curve_bytes);
	if (ret) {
		EMSG("Fail to transfer montgomery p from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(a, a, msg->key_bytes, msg->curve_bytes);
	if (ret) {
		EMSG("Fail to transfer montgomery a from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(k, k, msg->key_bytes, msg->curve_bytes);
	if (ret) {
		EMSG("Fail to transfer montgomery k from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(x, x, msg->key_bytes, msg->x_bytes);
	if (ret) {
		EMSG("Fail to transfer montgomery x from crypto_bin to hpre_bin");
		return ret;
	}

	return hpre_montgomery_params_pretreatment(msg);
}

static TEE_Result
hpre_montgomery_request_init(const struct hpre_mgm_curve *curve,
			     struct hpre_montgomery_msg *msg,
			     uint8_t *privkey,
			     uint8_t *pubkey)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	msg->alg_type = HPRE_ALG_X_DH_MULTIPLY;
	msg->curve_bytes = BITS_TO_BYTES(curve->key_bits);

	if (curve->key_bits == X25519_KEY_BITS) {
		msg->key_bytes = BITS_TO_BYTES(HPRE_HW_X25519_KBITS);
	} else if (curve->key_bits == X448_KEY_BITS) {
		msg->key_bytes = BITS_TO_BYTES(HPRE_HW_X448_KBITS);
	} else {
		EMSG("Curve key bits param error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = hpre_montgomery_params_alloc(msg);
	if (ret)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = hpre_montgomery_params_fill(curve, msg, privkey, pubkey);
	if (ret) {
		hpre_montgomery_params_free(msg);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static void hpre_montgomery_request_deinit(struct hpre_montgomery_msg *msg)
{
	hpre_montgomery_params_free(msg);
}

static enum hisi_drv_status hpre_montgomery_fill_sqe(void *bd, void *info)
{
	struct hpre_montgomery_msg *msg = info;
	struct hpre_sqe *sqe = bd;

	sqe->w0 = msg->alg_type | SHIFT_U32(0x1, HPRE_DONE_SHIFT);
	sqe->task_len1 = TASK_LENGTH(msg->key_bytes);
	sqe->key = msg->key_dma;
	sqe->in = msg->in_dma;
	sqe->out = msg->out_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status hpre_montgomery_parse_sqe(void *bd, void *info)
{
	struct hpre_montgomery_msg *msg = info;
	struct hpre_sqe *sqe = bd;
	uint8_t *rx = msg->out;
	uint16_t err = 0;
	uint16_t err1 = 0;
	uint16_t done = 0;

	err = HPRE_TASK_ETYPE(sqe->w0);
	err1 = HPRE_TASK_ETYPE1(sqe->w0);
	done = HPRE_TASK_DONE(sqe->w0);
	if (done != HPRE_HW_TASK_DONE || err || err1) {
		EMSG("HPRE do x_dh fail! done=0x%"PRIX16", etype=0x%"PRIX16",etype1=0x%"PRIX16,
		     done, err, err1);
		if (done == HPRE_HW_TASK_INIT) {
			msg->result = HISI_QM_DRVCRYPT_ENOPROC;
			return HISI_QM_DRVCRYPT_ENOPROC;
		}

		msg->result = HISI_QM_DRVCRYPT_IN_EPARA;
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	if (hpre_bin_to_crypto_bin(rx, rx, msg->key_bytes, msg->curve_bytes)) {
		EMSG("Fail to transfer x_dh out from hpre_bin to crypto_bin");
		msg->result = HISI_QM_DRVCRYPT_EINVAL;
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result hpre_montgomery_do_task(struct hpre_montgomery_msg *msg)
{
	struct hisi_qp *montgomery_qp = NULL;
	TEE_Result res = TEE_SUCCESS;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	montgomery_qp = hpre_create_qp(HISI_QM_CHANNEL_TYPE1);
	if (!montgomery_qp) {
		EMSG("Fail to create montgomery qp");
		return TEE_ERROR_BUSY;
	}

	montgomery_qp->fill_sqe = hpre_montgomery_fill_sqe;
	montgomery_qp->parse_sqe = hpre_montgomery_parse_sqe;
	ret = hisi_qp_send(montgomery_qp, msg);
	if (ret) {
		EMSG("Fail to send task, ret=%d", ret);
		res = TEE_ERROR_BAD_STATE;
		goto done;
	}

	ret = hisi_qp_recv_sync(montgomery_qp, msg);
	if (ret) {
		EMSG("Recv task error, ret=%d", ret);
		res = TEE_ERROR_BAD_STATE;
	}

done:
	hisi_qm_release_qp(montgomery_qp);

	return res;
}

static TEE_Result hpre_montgomery_gen_keypair(struct montgomery_keypair *key,
					      size_t size_bits)
{
	struct hpre_montgomery_msg msg = { };
	const struct hpre_mgm_curve *curve = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!key || !key->priv || !key->pub) {
		EMSG("Invalid montgomery_gen_keypair input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (size_bits == X25519_KEY_BITS)
		curve = &g_curve_list[X25519_CURVE_INDEX];
	else if (size_bits == X448_KEY_BITS)
		curve = &g_curve_list[X448_CURVE_INDEX];
	else
		return TEE_ERROR_BAD_PARAMETERS;

	ret = gen_random_privkey(key->priv, size_bits);
	if (ret) {
		EMSG("Fail to gen privkey");
		return ret;
	}

	ret = hpre_montgomery_request_init(curve, &msg, key->priv, NULL);
	if (ret) {
		EMSG("Fail to init montgomery key pair");
		return ret;
	}

	ret = hpre_montgomery_do_task(&msg);
	if (ret) {
		EMSG("Fail to do montgomery key pair task ret = 0x%"PRIX32, ret);
		goto done;
	}
	memcpy(key->pub, msg.out, msg.curve_bytes);

done:
	hpre_montgomery_request_deinit(&msg);

	return ret;
}

static TEE_Result
hpre_montgomery_do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	struct hpre_montgomery_msg msg = { };
	const struct hpre_mgm_curve *curve = NULL;
	struct montgomery_keypair *key = NULL;
	uint8_t *pubkey = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!sdata || !sdata->key_priv || !sdata->key_pub) {
		EMSG("Invalid montgomery_do_shared_secret input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key = sdata->key_priv;
	pubkey = sdata->key_pub;
	if (sdata->size_sec == BITS_TO_BYTES(X25519_KEY_BITS))
		curve = &g_curve_list[X25519_CURVE_INDEX];
	else if (sdata->size_sec == BITS_TO_BYTES(X448_KEY_BITS))
		curve = &g_curve_list[X448_CURVE_INDEX];
	else
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hpre_montgomery_request_init(curve, &msg, key->priv, pubkey);
	if (ret) {
		EMSG("Fail to init montgomery shared secret");
		return ret;
	}

	ret = hpre_montgomery_do_task(&msg);
	if (ret) {
		EMSG("Fail to do montgomery shared secret task! ret = 0x%"PRIX32,
		     ret);
		goto done;
	}
	memcpy(sdata->secret.data, msg.out, msg.curve_bytes);
	sdata->secret.length = msg.curve_bytes;
	memzero_explicit(msg.out, msg.curve_bytes);

done:
	hpre_montgomery_request_deinit(&msg);

	return ret;
}

static struct drvcrypt_montgomery driver_x25519 = {
	.alloc_keypair = hpre_montgomery_alloc_keypair,
	.gen_keypair = hpre_montgomery_gen_keypair,
	.shared_secret = hpre_montgomery_do_shared_secret,
};

static struct drvcrypt_montgomery driver_x448 = {
	.alloc_keypair = hpre_montgomery_alloc_keypair,
	.gen_keypair = hpre_montgomery_gen_keypair,
	.shared_secret = hpre_montgomery_do_shared_secret,
};

static TEE_Result hpre_montgomery_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_x25519(&driver_x25519);
	if (ret != TEE_SUCCESS) {
		EMSG("Hpre x25519 register to crypto fail");
		return ret;
	}

	ret = drvcrypt_register_x448(&driver_x448);
	if (ret != TEE_SUCCESS) {
		EMSG("Hpre x448 register to crypto fail");
		return ret;
	}

	return ret;
}

driver_init(hpre_montgomery_init);
