// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2024, HiSilicon Technologies Co., Ltd.
 * Kunpeng hardware accelerator hpre rsa algorithm implementation.
 */

#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <initcall.h>
#include <malloc.h>
#include <mbedtls/rsa.h>
#include <rng_support.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>

#include "hpre_main.h"
#include "hpre_rsa.h"

static enum hisi_drv_status hpre_rsa_fill_addr_params(struct hpre_rsa_msg *msg,
						      struct hpre_sqe *sqe)
{
	switch (msg->alg_type) {
	case HPRE_ALG_NC_NCRT:
	case HPRE_ALG_NC_CRT:
		if (msg->is_private) {
			/* DECRYPT */
			sqe->key = msg->prikey_dma;
			sqe->in = msg->in_dma;
			sqe->out = msg->out_dma;
		} else {
			/* ENCRYPT */
			sqe->key = msg->pubkey_dma;
			sqe->in = msg->in_dma;
			sqe->out = msg->out_dma;
		}
		return HISI_QM_DRVCRYPT_NO_ERR;
	default:
		EMSG("Invalid alg_type[%"PRIu32"]", msg->alg_type);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}
}

static enum hisi_drv_status hpre_rsa_fill_sqe(void *bd, void *info)
{
	struct hpre_rsa_msg *msg = info;
	struct hpre_sqe *sqe = bd;

	sqe->w0 = msg->alg_type | SHIFT_U32(0x1, HPRE_DONE_SHIFT);
	sqe->task_len1 = TASK_LENGTH(msg->key_bytes);

	return hpre_rsa_fill_addr_params(msg, sqe);
}

static enum hisi_drv_status hpre_rsa_parse_sqe(void *bd, void *info __unused)
{
	struct hpre_sqe *sqe = bd;
	uint16_t err = 0;
	uint16_t done = 0;

	err = HPRE_TASK_ETYPE(sqe->w0);
	done = HPRE_TASK_DONE(sqe->w0);
	if (done != HPRE_HW_TASK_DONE || err) {
		EMSG("HPRE do rsa fail! done=0x%"PRIX16", etype=0x%"PRIX16,
		     done, err);
		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result hpre_rsa_do_task(void *msg)
{
	struct hisi_qp *rsa_qp = NULL;
	TEE_Result res = TEE_SUCCESS;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	rsa_qp = hpre_create_qp(HISI_QM_CHANNEL_TYPE0);
	if (!rsa_qp) {
		EMSG("Fail to create rsa qp");
		return TEE_ERROR_BUSY;
	}

	rsa_qp->fill_sqe = hpre_rsa_fill_sqe;
	rsa_qp->parse_sqe = hpre_rsa_parse_sqe;
	ret = hisi_qp_send(rsa_qp, msg);
	if (ret) {
		EMSG("Fail to send task, ret=%x"PRIx32, ret);
		res = TEE_ERROR_BAD_STATE;
		goto done_proc;
	}

	ret = hisi_qp_recv_sync(rsa_qp, msg);
	if (ret) {
		EMSG("Recv task error, ret=%x"PRIx32, ret);
		res = TEE_ERROR_BAD_STATE;
		goto done_proc;
	}

done_proc:
	hisi_qm_release_qp(rsa_qp);

	return res;
}

static TEE_Result mgf_process(size_t digest_size, uint8_t *seed,
			      size_t seed_len, uint8_t *mask, size_t mask_len,
			      struct drvcrypt_rsa_ed *rsa_data)
{
	struct drvcrypt_rsa_mgf mgf = { };

	if (!rsa_data->mgf) {
		EMSG("mgf function is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mgf.hash_algo = rsa_data->hash_algo;
	mgf.digest_size = digest_size;
	mgf.seed.data = seed;
	mgf.seed.length = seed_len;
	mgf.mask.data = mask;
	mgf.mask.length = mask_len;

	return rsa_data->mgf(&mgf);
}

static TEE_Result xor_process(uint8_t *a, uint8_t *b, uint8_t *out, size_t len)
{
	struct drvcrypt_mod_op xor_mod = { };

	xor_mod.n.length = len;
	xor_mod.a.data = a;
	xor_mod.a.length = len;
	xor_mod.b.data = b;
	xor_mod.b.length = len;
	xor_mod.result.data = out;
	xor_mod.result.length = len;

	return drvcrypt_xor_mod_n(&xor_mod);
}

static size_t hpre_rsa_get_hw_kbytes(size_t key_bits)
{
	size_t size = 0;

	if (key_bits <= 1024)
		size = BITS_TO_BYTES(1024);
	else if (key_bits <= 2048)
		size = BITS_TO_BYTES(2048);
	else if (key_bits <= 3072)
		size = BITS_TO_BYTES(3072);
	else if (key_bits <= 4096)
		size = BITS_TO_BYTES(4096);
	else
		EMSG("Invalid key_bits[%zu]", key_bits);

	return size;
}

static void hpre_rsa_params_free(struct hpre_rsa_msg *msg)
{
	switch (msg->alg_type) {
	case HPRE_ALG_NC_NCRT:
		if (msg->is_private)
			free_wipe(msg->prikey);
		else
			free(msg->pubkey);
		break;
	case HPRE_ALG_NC_CRT:
		if (msg->is_private)
			free_wipe(msg->prikey);
		break;
	default:
		EMSG("Invalid alg_type[%"PRIu32"]", msg->alg_type);
		break;
	}
}

static enum hisi_drv_status hpre_rsa_encrypt_alloc(struct hpre_rsa_msg *msg)
{
	uint32_t size = HPRE_RSA_NCRT_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc rsa ncrt buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->pubkey = data;
	msg->pubkey_dma = virt_to_phys(msg->pubkey);

	msg->in = data + (msg->key_bytes * 2);
	msg->in_dma = msg->pubkey_dma + (msg->key_bytes * 2);

	msg->out = msg->in + msg->key_bytes;
	msg->out_dma = msg->in_dma + msg->key_bytes;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status
hpre_rsa_encrypt_bn2bin(struct hpre_rsa_msg *msg,
			struct drvcrypt_rsa_ed *rsa_data)
{
	struct rsa_public_key *key = rsa_data->key.key;
	uint32_t e_len = 0;
	uint32_t n_len = 0;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	uint8_t *n = NULL;

	n = msg->pubkey + msg->key_bytes;

	crypto_bignum_bn2bin(key->e, msg->pubkey);
	crypto_bignum_bn2bin(key->n, n);
	e_len = crypto_bignum_num_bytes(key->e);
	n_len = crypto_bignum_num_bytes(key->n);

	ret = hpre_bin_from_crypto_bin(msg->pubkey, msg->pubkey,
				       msg->key_bytes, e_len);
	if (ret) {
		EMSG("Fail to transfer rsa ncrt e from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(n, n, msg->key_bytes, n_len);
	if (ret) {
		EMSG("Fail to transfer rsa ncrt n from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(msg->in, rsa_data->message.data,
				       msg->key_bytes,
				       rsa_data->message.length);
	if (ret)
		EMSG("Fail to transfer rsa plaintext from crypto_bin to hpre_bin");

	return ret;
}

static TEE_Result hpre_rsa_encrypt_init(struct hpre_rsa_msg *msg,
					struct drvcrypt_rsa_ed *rsa_data)
{
	size_t n_bytes = rsa_data->key.n_size;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	msg->alg_type = HPRE_ALG_NC_NCRT;
	msg->is_private = rsa_data->key.isprivate;
	msg->key_bytes = hpre_rsa_get_hw_kbytes(BYTES_TO_BITS(n_bytes));
	if (!msg->key_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hpre_rsa_encrypt_alloc(msg);
	if (ret)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = hpre_rsa_encrypt_bn2bin(msg, rsa_data);
	if (ret) {
		hpre_rsa_params_free(msg);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result rsa_nopad_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	size_t n_bytes = rsa_data->key.n_size;
	struct hpre_rsa_msg msg = { };
	TEE_Result ret = TEE_SUCCESS;

	if (rsa_data->message.length > n_bytes) {
		EMSG("Invalid msg length[%zu]", rsa_data->message.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = hpre_rsa_encrypt_init(&msg, rsa_data);
	if (ret) {
		EMSG("Fail to init rsa msg");
		return ret;
	}

	ret = hpre_rsa_do_task(&msg);
	if (ret)
		goto encrypt_deinit;

	/* Ciphertext can have valid zero data in NOPAD MODE */
	memcpy(rsa_data->cipher.data, msg.out + msg.key_bytes - n_bytes,
	       n_bytes);
	rsa_data->cipher.length = n_bytes;

encrypt_deinit:
	hpre_rsa_params_free(&msg);

	return ret;
}

static TEE_Result pkcs_v1_5_fill_ps(uint8_t *ps, size_t ps_len)
{
	size_t i = 0;

	if (hw_get_random_bytes(ps, ps_len)) {
		EMSG("Fail to get ps data");
		return TEE_ERROR_NO_DATA;
	}

	for (i = 0; i < ps_len; i++) {
		if (ps[i] == 0)
			ps[i] = PKCS_V1_5_PS_DATA;
	}

	return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs_v1_5_encode(struct drvcrypt_rsa_ed *rsa_data,
					 uint8_t *out)
{
	size_t msg_len = rsa_data->message.length;
	size_t out_len = rsa_data->cipher.length;
	size_t n_bytes = rsa_data->key.n_size;
	uint8_t *ps = out + PKCS_V1_5_PS_POS;
	TEE_Result ret = TEE_SUCCESS;
	size_t ps_len = 0;

	/* PKCS_V1.5 format 0x00 || 0x02 || PS non-zero || 0x00 || M */
	if ((msg_len + PKCS_V1_5_MSG_MIN_LEN) > n_bytes || out_len < n_bytes) {
		EMSG("Invalid pkcs_v1.5 encode parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ps_len = n_bytes - PKCS_V1_5_FIXED_LEN - msg_len;
	ret = pkcs_v1_5_fill_ps(ps, ps_len);
	if (ret)
		return ret;

	out[0] = 0;
	out[1] = ENCRYPT_PAD;
	out[PKCS_V1_5_FIXED_LEN + ps_len - 1] = 0;
	memcpy(out + PKCS_V1_5_FIXED_LEN + ps_len, rsa_data->message.data,
	       msg_len);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	uint32_t n_bytes = rsa_data->key.n_size;
	struct drvcrypt_rsa_ed rsa_enc_info = *rsa_data;
	TEE_Result ret = TEE_SUCCESS;

	/* Alloc pkcs_v1.5 encode message data buf */
	rsa_enc_info.message.data = malloc(n_bytes);
	if (!rsa_enc_info.message.data) {
		EMSG("Fail to alloc message data buf");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	rsa_enc_info.message.length = n_bytes;
	ret = rsaes_pkcs_v1_5_encode(rsa_data, rsa_enc_info.message.data);
	if (ret) {
		EMSG("Fail to get pkcs_v1.5 encode message data");
		goto free_data;
	}

	ret = rsa_nopad_encrypt(&rsa_enc_info);
	if (ret)
		goto free_data;

	memcpy(rsa_data->cipher.data, rsa_enc_info.cipher.data,
	       rsa_enc_info.cipher.length);
	rsa_data->cipher.length = rsa_enc_info.cipher.length;

free_data:
	free(rsa_enc_info.message.data);

	return ret;
}

static TEE_Result rsa_oaep_fill_db(struct drvcrypt_rsa_ed *rsa_data,
				   uint8_t *db)
{
	size_t lhash_len = rsa_data->digest_size;
	size_t n_bytes = rsa_data->key.n_size;
	size_t db_len = n_bytes - lhash_len - 1;
	size_t ps_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	/* oaep db format lhash || ps zero || 01 || M */
	ret = tee_hash_createdigest(rsa_data->hash_algo, rsa_data->label.data,
				    rsa_data->label.length, db, lhash_len);
	if (ret) {
		EMSG("Fail to get label hash");
		return ret;
	}

	ps_len = db_len - lhash_len - rsa_data->message.length - 1;
	db[lhash_len + ps_len] = 1;
	memcpy(db + lhash_len + ps_len + 1, rsa_data->message.data,
	       rsa_data->message.length);

	return TEE_SUCCESS;
}

static TEE_Result rsa_oaep_fill_maskdb(struct drvcrypt_rsa_ed *rsa_data,
				       uint8_t *seed, uint8_t *db,
				       uint8_t *mask_db)
{
	size_t lhash_len = rsa_data->digest_size;
	size_t n_bytes = rsa_data->key.n_size;
	size_t db_len = n_bytes - lhash_len - 1;
	uint8_t seed_mgf[OAEP_MAX_DB_LEN] = { };
	TEE_Result ret = TEE_SUCCESS;

	ret = mgf_process(lhash_len, seed, lhash_len, seed_mgf, db_len,
			  rsa_data);
	if (ret) {
		EMSG("Fail to get seed_mgf");
		return ret;
	}

	return xor_process(db, seed_mgf, mask_db, db_len);
}

static TEE_Result rsa_oaep_fill_maskseed(struct drvcrypt_rsa_ed *rsa_data,
					 uint8_t *seed, uint8_t *em)
{
	uint8_t mask_db_mgf[OAEP_MAX_HASH_LEN] = { 0 };
	size_t lhash_len = rsa_data->digest_size;
	size_t n_bytes = rsa_data->key.n_size;
	size_t db_len = n_bytes - lhash_len - 1;
	uint8_t *mask_db = em + lhash_len + 1;
	uint8_t *mask_seed = em + 1;
	TEE_Result ret = TEE_SUCCESS;

	ret = mgf_process(lhash_len, mask_db, db_len, mask_db_mgf, lhash_len,
			  rsa_data);
	if (ret) {
		EMSG("Fail to get mask_db_mgf");
		return ret;
	}

	return xor_process(seed, mask_db_mgf, mask_seed, lhash_len);
}

static TEE_Result rsa_oaep_encode(struct drvcrypt_rsa_ed *rsa_data,
				  uint8_t *em)
{
	size_t lhash_len = rsa_data->digest_size;
	uint8_t db[OAEP_MAX_DB_LEN] = { };
	uint8_t seed[OAEP_MAX_HASH_LEN] = { };
	TEE_Result ret = TEE_SUCCESS;

	/* oaep format 00 || maskedseed || maskeddb */
	em[0] = 0;

	ret = rsa_oaep_fill_db(rsa_data, db);
	if (ret)
		return ret;

	ret = hw_get_random_bytes(seed, lhash_len);
	if (ret)
		return ret;

	ret = rsa_oaep_fill_maskdb(rsa_data, seed, db, em + lhash_len + 1);
	if (ret)
		return ret;

	return rsa_oaep_fill_maskseed(rsa_data, seed, em);
}

static TEE_Result rsa_oaep_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	size_t n_bytes = rsa_data->key.n_size;
	struct drvcrypt_rsa_ed rsa_enc_info = *rsa_data;
	TEE_Result ret = TEE_SUCCESS;

	/* Alloc oaep encode message data buf */
	rsa_enc_info.message.data = malloc(n_bytes);
	if (!rsa_enc_info.message.data) {
		EMSG("Fail to alloc message data buf");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	rsa_enc_info.message.length = n_bytes;
	ret = rsa_oaep_encode(rsa_data, rsa_enc_info.message.data);
	if (ret) {
		EMSG("Fail to get oaep encode message data");
		goto free_data;
	}

	ret = rsa_nopad_encrypt(&rsa_enc_info);
	if (ret)
		goto free_data;

	memcpy(rsa_data->cipher.data, rsa_enc_info.cipher.data,
	       rsa_enc_info.cipher.length);
	rsa_data->cipher.length = rsa_enc_info.cipher.length;

free_data:
	free(rsa_enc_info.message.data);

	return ret;
}

static TEE_Result hpre_rsa_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	if (!rsa_data) {
		EMSG("Invalid rsa encrypt input parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
		return rsa_nopad_encrypt(rsa_data);
	case DRVCRYPT_RSA_PKCS_V1_5:
		return rsa_pkcs_encrypt(rsa_data);
	case DRVCRYPT_RSA_OAEP:
		return rsa_oaep_encrypt(rsa_data);
	default:
		EMSG("Invalid rsa id");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static enum hisi_drv_status hpre_rsa_crt_decrypt_alloc(struct hpre_rsa_msg *msg)
{
	uint32_t size = HPRE_RSA_CRT_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc rsa crt total buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->prikey = data;
	msg->prikey_dma = virt_to_phys(msg->prikey);

	msg->in = data + (msg->key_bytes * 2) + (msg->key_bytes >> 1);
	msg->in_dma = msg->prikey_dma + (msg->key_bytes * 2) +
		      (msg->key_bytes >> 1);

	msg->out = msg->in + msg->key_bytes;
	msg->out_dma = msg->in_dma + msg->key_bytes;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status
hpre_rsa_ncrt_decrypt_alloc(struct hpre_rsa_msg *msg)
{
	uint32_t size = HPRE_RSA_NCRT_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc rsa ncrt buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->prikey = data;
	msg->prikey_dma = virt_to_phys(msg->prikey);

	msg->in = data + (msg->key_bytes * 2);
	msg->in_dma = msg->prikey_dma + (msg->key_bytes * 2);

	msg->out = msg->in + msg->key_bytes;
	msg->out_dma = msg->in_dma + msg->key_bytes;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status
hpre_rsa_crt_decrypt_bn2bin(struct hpre_rsa_msg *msg,
			    struct drvcrypt_rsa_ed *rsa_data)
{
	struct rsa_keypair *key = rsa_data->key.key;
	uint32_t p_bytes = msg->key_bytes >> 1;
	uint32_t dq_len = crypto_bignum_num_bytes(key->dq);
	uint32_t dp_len = crypto_bignum_num_bytes(key->dp);
	uint32_t q_len = crypto_bignum_num_bytes(key->q);
	uint32_t p_len = crypto_bignum_num_bytes(key->p);
	uint32_t qp_len = crypto_bignum_num_bytes(key->qp);
	uint8_t *dq = msg->prikey;
	uint8_t *dp = msg->prikey + p_bytes;
	uint8_t *q = dp + p_bytes;
	uint8_t *p = q + p_bytes;
	uint8_t *qp = p + p_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	crypto_bignum_bn2bin(key->dq, dq);
	crypto_bignum_bn2bin(key->dp, dp);
	crypto_bignum_bn2bin(key->q, q);
	crypto_bignum_bn2bin(key->p, p);
	crypto_bignum_bn2bin(key->qp, qp);

	ret = hpre_bin_from_crypto_bin(dq, dq, p_bytes, dq_len);
	if (ret) {
		EMSG("Fail to transfer rsa crt dq from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(dp, dp, p_bytes, dp_len);
	if (ret) {
		EMSG("Fail to transfer rsa crt dp from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(q, q, p_bytes, q_len);
	if (ret) {
		EMSG("Fail to transfer rsa crt q from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(p, p, p_bytes, p_len);
	if (ret) {
		EMSG("Fail to transfer rsa crt p from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(qp, qp, p_bytes, qp_len);
	if (ret) {
		EMSG("Fail to transfer rsa crt qinv from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(msg->in, rsa_data->cipher.data,
				       msg->key_bytes, rsa_data->cipher.length);
	if (ret)
		EMSG("Fail to transfer rsa ciphertext from crypto_bin to hpre_bin");

	return ret;
}

static enum hisi_drv_status
hpre_rsa_ncrt_decrypt_bn2bin(struct hpre_rsa_msg *msg,
			     struct drvcrypt_rsa_ed *rsa_data)
{
	struct rsa_keypair *key = rsa_data->key.key;
	uint32_t d_len = 0;
	uint32_t n_len = 0;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	uint8_t *n = NULL;

	n = msg->prikey + msg->key_bytes;

	crypto_bignum_bn2bin(key->d, msg->prikey);
	crypto_bignum_bn2bin(key->n, n);
	d_len = crypto_bignum_num_bytes(key->d);
	n_len = crypto_bignum_num_bytes(key->n);

	ret = hpre_bin_from_crypto_bin(msg->prikey, msg->prikey, msg->key_bytes,
				       d_len);
	if (ret) {
		EMSG("Fail to transfer rsa ncrt d from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(n, n, msg->key_bytes, n_len);
	if (ret) {
		EMSG("Fail to transfer rsa ncrt n from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(msg->in, rsa_data->cipher.data,
				       msg->key_bytes, rsa_data->cipher.length);
	if (ret)
		EMSG("Fail to transfer rsa ciphertext from crypto_bin to hpre_bin");

	return ret;
}

static bool hpre_rsa_is_crt_mod(struct rsa_keypair *key)
{
	if (key->p && crypto_bignum_num_bits(key->p) &&
	    key->q && crypto_bignum_num_bits(key->q) &&
	    key->dp && crypto_bignum_num_bits(key->dp) &&
	    key->dq && crypto_bignum_num_bits(key->dq) &&
	    key->qp && crypto_bignum_num_bits(key->qp))
		return true;

	return false;
}

static TEE_Result hpre_rsa_decrypt_init(struct hpre_rsa_msg *msg,
					struct drvcrypt_rsa_ed *rsa_data)
{
	struct rsa_keypair *key = rsa_data->key.key;
	size_t n_bytes = rsa_data->key.n_size;
	bool is_crt = false;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	msg->is_private = rsa_data->key.isprivate;
	msg->key_bytes = hpre_rsa_get_hw_kbytes(BYTES_TO_BITS(n_bytes));
	if (!msg->key_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	is_crt = hpre_rsa_is_crt_mod(key);
	if (is_crt) {
		msg->alg_type = HPRE_ALG_NC_CRT;
		ret = hpre_rsa_crt_decrypt_alloc(msg);
		if (ret)
			return TEE_ERROR_OUT_OF_MEMORY;

		ret = hpre_rsa_crt_decrypt_bn2bin(msg, rsa_data);
		if (ret) {
			hpre_rsa_params_free(msg);
			return TEE_ERROR_BAD_STATE;
		}
	} else {
		msg->alg_type = HPRE_ALG_NC_NCRT;
		ret = hpre_rsa_ncrt_decrypt_alloc(msg);
		if (ret)
			return TEE_ERROR_OUT_OF_MEMORY;

		ret = hpre_rsa_ncrt_decrypt_bn2bin(msg, rsa_data);
		if (ret) {
			hpre_rsa_params_free(msg);
			return TEE_ERROR_BAD_STATE;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result rsa_nopad_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	size_t n_bytes = rsa_data->key.n_size;
	struct hpre_rsa_msg msg = { };
	uint32_t offset = 0;
	TEE_Result ret = TEE_SUCCESS;
	uint8_t *pos = NULL;

	if (rsa_data->cipher.length > n_bytes) {
		EMSG("Invalid cipher length[%zu]", rsa_data->cipher.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = hpre_rsa_decrypt_init(&msg, rsa_data);
	if (ret) {
		EMSG("Fail to init rsa msg");
		return ret;
	}

	ret = hpre_rsa_do_task(&msg);
	if (ret)
		goto decrypt_deinit;

	pos = msg.out + msg.key_bytes - n_bytes;
	if (rsa_data->rsa_id == DRVCRYPT_RSA_NOPAD) {
		/* Plaintext can not have valid zero data in NOPAD MODE */
		while ((offset < n_bytes - 1) && (pos[offset] == 0))
			offset++;
	}

	rsa_data->message.length = n_bytes - offset;
	memcpy(rsa_data->message.data, pos + offset, rsa_data->message.length);

decrypt_deinit:
	hpre_rsa_params_free(&msg);

	return ret;
}

static TEE_Result rsaes_pkcs_v1_5_decode(struct drvcrypt_rsa_ed *rsa_data,
					 uint8_t *out, size_t *out_len)
{
	size_t em_len = rsa_data->message.length;
	uint8_t *em = rsa_data->message.data;
	size_t ps_len = 0;
	size_t i = 0;

	/* PKCS_V1.5 EM format 0x00 || 0x02 || PS non-zero || 0x00 || M */
	if (em_len < PKCS_V1_5_MSG_MIN_LEN || em[0] != 0 ||
	    em[1] != ENCRYPT_PAD) {
		EMSG("Invalid pkcs_v1.5 decode parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	for (i = PKCS_V1_5_PS_POS; i < em_len; i++) {
		if (em[i] == 0)
			break;
	}

	if (i >= em_len) {
		EMSG("Fail to find zero pos");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ps_len = i - PKCS_V1_5_PS_POS;
	if (em_len - ps_len - PKCS_V1_5_FIXED_LEN > *out_len ||
	    ps_len < PKCS_V1_5_PS_MIN_LEN) {
		EMSG("Invalid pkcs_v1.5 decode ps_len");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*out_len = em_len - ps_len - PKCS_V1_5_FIXED_LEN;
	memcpy(out, em + ps_len + PKCS_V1_5_FIXED_LEN, *out_len);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	uint32_t n_bytes = rsa_data->key.n_size;
	struct drvcrypt_rsa_ed rsa_dec_info = *rsa_data;
	TEE_Result ret = TEE_SUCCESS;

	/* Alloc pkcs_v1.5 encode message data buf */
	rsa_dec_info.message.data = malloc(n_bytes);
	if (!rsa_dec_info.message.data) {
		EMSG("Fail to alloc message data buf");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	rsa_dec_info.message.length = n_bytes;
	ret = rsa_nopad_decrypt(&rsa_dec_info);
	if (ret)
		goto free_data;

	ret = rsaes_pkcs_v1_5_decode(&rsa_dec_info, rsa_data->message.data,
				     &rsa_data->message.length);
	if (ret)
		EMSG("Fail to get pkcs_v1.5 decode message data");

free_data:
	free(rsa_dec_info.message.data);

	return ret;
}

static TEE_Result rsa_oaep_get_seed(struct drvcrypt_rsa_ed *rsa_data,
				    uint8_t *mask_db, uint8_t *seed)
{
	size_t db_len = rsa_data->key.n_size - rsa_data->digest_size - 1;
	uint8_t mask_db_mgf[OAEP_MAX_HASH_LEN] = { };
	size_t lhash_len = rsa_data->digest_size;
	uint8_t *mask_seed = NULL;
	TEE_Result ret = TEE_SUCCESS;

	mask_seed = rsa_data->message.data + 1;

	ret = mgf_process(lhash_len, mask_db, db_len, mask_db_mgf, lhash_len,
			  rsa_data);
	if (ret) {
		EMSG("Fail to get mask_db mgf result");
		return ret;
	}

	return xor_process(mask_seed, mask_db_mgf, seed, lhash_len);
}

static TEE_Result rsa_oaep_get_db(struct drvcrypt_rsa_ed *rsa_data,
				  uint8_t *mask_db, uint8_t *seed, uint8_t *db)
{
	size_t db_len = rsa_data->key.n_size - rsa_data->digest_size - 1;
	size_t lhash_len = rsa_data->digest_size;
	uint8_t seed_mgf[OAEP_MAX_DB_LEN] = { };
	TEE_Result ret = TEE_SUCCESS;

	ret = mgf_process(lhash_len, seed, lhash_len, seed_mgf, db_len,
			  rsa_data);
	if (ret) {
		EMSG("Fail to get seed mgf result");
		return ret;
	}

	return xor_process(mask_db, seed_mgf, db, db_len);
}

static TEE_Result rsa_oaep_get_msg(struct drvcrypt_rsa_ed *rsa_data,
				   uint8_t *db, uint8_t *out, size_t *out_len)
{
	size_t db_len = rsa_data->key.n_size - rsa_data->digest_size - 1;
	size_t lhash_len = rsa_data->digest_size;
	uint8_t hash[OAEP_MAX_HASH_LEN] = { };
	size_t msg_len = 0;
	size_t lp_len = 0;
	TEE_Result ret = TEE_SUCCESS;

	/* oaep db format lhash || ps zero || 01 || M */
	ret = tee_hash_createdigest(rsa_data->hash_algo, rsa_data->label.data,
				    rsa_data->label.length, hash, lhash_len);
	if (ret) {
		EMSG("Fail to get label hash");
		return ret;
	}

	if (memcmp(hash, db, lhash_len)) {
		EMSG("Hash is not equal");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	for (lp_len = lhash_len; lp_len < db_len; lp_len++) {
		if (db[lp_len] != 0)
			break;
	}

	if (lp_len == db_len) {
		EMSG("Fail to find fixed 01 in db");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	msg_len = db_len - lp_len - 1;
	if (msg_len > rsa_data->message.length) {
		DMSG("Message space is not enough");
		*out_len = msg_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	*out_len = msg_len;
	memcpy(out, db + lp_len + 1, msg_len);

	return TEE_SUCCESS;
}

static TEE_Result rsa_oaep_decode(struct drvcrypt_rsa_ed *rsa_data,
				  uint8_t *out, size_t *out_len)
{
	size_t lhash_len = rsa_data->digest_size;
	uint8_t seed[OAEP_MAX_HASH_LEN] = { };
	uint8_t db[OAEP_MAX_DB_LEN] = { };
	uint8_t *mask_db = NULL;
	TEE_Result ret = TEE_SUCCESS;

	/* oaep format 00 || maskedseed || maskeddb */
	mask_db = rsa_data->message.data + lhash_len + 1;
	ret = rsa_oaep_get_seed(rsa_data, mask_db, seed);
	if (ret)
		return ret;

	ret = rsa_oaep_get_db(rsa_data, mask_db, seed, db);
	if (ret)
		return ret;

	return rsa_oaep_get_msg(rsa_data, db, out, out_len);
}

static TEE_Result rsa_oaep_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	size_t n_bytes = rsa_data->key.n_size;
	struct drvcrypt_rsa_ed rsa_dec_info = *rsa_data;
	TEE_Result ret = TEE_SUCCESS;

	/* Alloc oaep encode message data buf */
	rsa_dec_info.message.data = malloc(n_bytes);
	if (!rsa_dec_info.message.data) {
		EMSG("Fail to alloc message data buf");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	rsa_dec_info.message.length = n_bytes;
	ret = rsa_nopad_decrypt(&rsa_dec_info);
	if (ret)
		goto free_data;

	ret = rsa_oaep_decode(&rsa_dec_info, rsa_data->message.data,
			      &rsa_data->message.length);
	if (ret)
		EMSG("Fail to get oaep decode message data");

free_data:
	free(rsa_dec_info.message.data);

	return ret;
}

static TEE_Result hpre_rsa_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	if (!rsa_data) {
		EMSG("Invalid rsa decrypt input parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
		return rsa_nopad_decrypt(rsa_data);
	case DRVCRYPT_RSA_PKCS_V1_5:
		return rsa_pkcs_decrypt(rsa_data);
	case DRVCRYPT_RSA_OAEP:
		return rsa_oaep_decrypt(rsa_data);
	default:
		EMSG("Invalid rsa id");
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static const struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = sw_crypto_acipher_alloc_rsa_keypair,
	.alloc_publickey = sw_crypto_acipher_alloc_rsa_public_key,
	.free_publickey = sw_crypto_acipher_free_rsa_public_key,
	.free_keypair = sw_crypto_acipher_free_rsa_keypair,
	.gen_keypair = sw_crypto_acipher_gen_rsa_key,
	.encrypt = hpre_rsa_encrypt,
	.decrypt = hpre_rsa_decrypt,
	.optional = {
		/*
		 * If ssa_sign or verify is NULL, the framework will fill
		 * data format directly by soft calculation. Then call api
		 * encrypt or decrypt.
		 */
		.ssa_sign = NULL,
		.ssa_verify = NULL,
	},
};

static TEE_Result hpre_rsa_init(void)
{
	TEE_Result ret = drvcrypt_register_rsa(&driver_rsa);

	if (ret != TEE_SUCCESS)
		EMSG("hpre rsa register to crypto fail");

	return ret;
}

driver_init(hpre_rsa_init);
