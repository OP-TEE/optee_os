// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

#define RSA_MAX_PRIV_EXP_LEN	512
#define RSA_MAX_PUB_EXP_LEN	4
#define RSA_MAX_MOD_LEN		512

static void crypto_bignum_bn2bin_pad(size_t size,
				     struct bignum *from, uint8_t *to)
{
	size_t len = crypto_bignum_num_bytes(from);

	crypto_bignum_bn2bin(from, to + size - len);
}

static TEE_Result do_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	struct rsa_public_key *p = rsa_data->key.key;
	struct versal_rsa_input_param *cmd = NULL;
	struct versal_mbox_mem cmd_buf = { };
	struct versal_mbox_mem cipher = { };
	struct versal_mbox_mem key = { };
	struct versal_mbox_mem msg = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	uint32_t err = 0;

	if (rsa_data->key.n_size == 128)
		return TEE_ERROR_NOT_IMPLEMENTED;

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSASSA_PSS:
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSA_OAEP:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case DRVCRYPT_RSASSA_PKCS_V1_5:
		/* IP also supports SHA3-384 - but requires TEE Core API 1.3 */
		if (rsa_data->hash_algo == TEE_ALG_SHA1)
			return TEE_ERROR_NOT_IMPLEMENTED;
		break;
	default:
		panic();
	}

	versal_mbox_alloc(RSA_MAX_MOD_LEN + RSA_MAX_PUB_EXP_LEN, NULL, &key);
	crypto_bignum_bn2bin_pad(rsa_data->key.n_size, p->n, key.buf);
	crypto_bignum_bn2bin_pad(RSA_MAX_PUB_EXP_LEN,
				 p->e, (uint8_t *)key.buf + RSA_MAX_MOD_LEN);

	versal_mbox_alloc(rsa_data->message.length, rsa_data->message.data,
			  &msg);
	versal_mbox_alloc(rsa_data->cipher.length, NULL, &cipher);
	versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);

	cmd = cmd_buf.buf;
	cmd->key_len = rsa_data->key.n_size;
	cmd->data_addr = virt_to_phys(msg.buf);
	cmd->key_addr = virt_to_phys(key.buf);

	arg.ibuf[0].mem = cmd_buf;
	arg.ibuf[1].mem = cipher;
	arg.ibuf[2].mem = msg;
	arg.ibuf[3].mem = key;

	if (versal_crypto_request(RSA_PUBLIC_ENCRYPT, &arg, &err)) {
		EMSG("Versal RSA: encrypt: error 0x%x", err);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	memcpy(rsa_data->cipher.data, cipher.buf, rsa_data->key.n_size);
	rsa_data->cipher.length = rsa_data->key.n_size;

	ret = TEE_SUCCESS;
out:
	free(cipher.buf);
	free(cmd);
	free(msg.buf);
	free(key.buf);

	return ret;
}

static TEE_Result do_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	struct versal_rsa_input_param *cmd = NULL;
	struct rsa_keypair *p = rsa_data->key.key;
	struct versal_mbox_mem cmd_buf = { };
	struct versal_mbox_mem cipher = { };
	struct versal_mbox_mem key = { };
	struct versal_mbox_mem msg = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	uint32_t err = 0;

	if (rsa_data->key.n_size == 128)
		return TEE_ERROR_NOT_IMPLEMENTED;

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSASSA_PSS:
	case DRVCRYPT_RSA_OAEP:
	case DRVCRYPT_RSA_NOPAD:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case DRVCRYPT_RSASSA_PKCS_V1_5:
		/* IP too supports SHA-3-384 - but requires TEE Core API 1.3 */
		if (rsa_data->hash_algo == TEE_ALG_SHA1)
			return TEE_ERROR_NOT_IMPLEMENTED;

		break;
	default:
		panic();
	}

	versal_mbox_alloc(RSA_MAX_MOD_LEN + RSA_MAX_PRIV_EXP_LEN, NULL, &key);
	crypto_bignum_bn2bin_pad(rsa_data->key.n_size, p->n, key.buf);
	crypto_bignum_bn2bin_pad(rsa_data->key.n_size, p->d,
				 (uint8_t *)key.buf + RSA_MAX_MOD_LEN);

	versal_mbox_alloc(rsa_data->cipher.length, rsa_data->cipher.data,
			  &cipher);
	versal_mbox_alloc(rsa_data->message.length, NULL, &msg);
	versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);

	cmd = cmd_buf.buf;
	cmd->key_len = rsa_data->key.n_size;
	cmd->data_addr = virt_to_phys(cipher.buf);
	cmd->key_addr = virt_to_phys(key.buf);

	arg.ibuf[0].mem = cmd_buf;
	arg.ibuf[1].mem = msg;
	arg.ibuf[2].mem = cipher;
	arg.ibuf[3].mem = key;

	if (versal_crypto_request(RSA_PRIVATE_DECRYPT, &arg, &err)) {
		EMSG("Versal RSA: decrypt: error 0x%x", err);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	rsa_data->message.length = rsa_data->key.n_size;
	memcpy(rsa_data->message.data, msg.buf, rsa_data->message.length);
	ret = TEE_SUCCESS;
out:
	free(cipher.buf);
	free(cmd);
	free(key.buf);
	free(msg.buf);

	return ret;
}

static TEE_Result do_ssa_sign(struct drvcrypt_rsa_ssa *ssa_data __unused)
{
	/* by returning NOT_IMPLEMENTED, we call back to this driver's
	 * do_decrypt function via drvcrypt_rsassa_sign (which also provides
	 * the pkcs padding to the message)
	 */
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_ssa_verify(struct drvcrypt_rsa_ssa *ssa_data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_gen_keypair(struct rsa_keypair *s __unused,
				 size_t size_bits __unused)
{
	/* delegate to software */
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_alloc_keypair(struct rsa_keypair *s __unused,
				   size_t size_bits __unused)
{
	/* delegate to software */
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_alloc_publickey(struct rsa_public_key *s __unused,
				     size_t size_bits __unused)
{
	/* delegate to software */
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static void do_free_publickey(struct rsa_public_key *s)
{
	/* delegate to software */
	sw_crypto_acipher_free_rsa_public_key(s);
}

static void do_free_keypair(struct rsa_keypair *s)
{
	/* delegate to software */
	sw_crypto_acipher_free_rsa_keypair(s);
}

static struct drvcrypt_rsa driver_rsa = {
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.alloc_keypair = do_alloc_keypair,
	.optional.ssa_verify = do_ssa_verify,
	.optional.ssa_sign = do_ssa_sign,
	.free_keypair = do_free_keypair,
	.gen_keypair = do_gen_keypair,
	.encrypt = do_encrypt,
	.decrypt = do_decrypt,
};

static TEE_Result rsa_init(void)
{
	struct cmd_args arg = { };

	if (versal_crypto_request(RSA_KAT, &arg, NULL))
		return TEE_ERROR_GENERIC;

	return drvcrypt_register_rsa(&driver_rsa);
}

driver_init(rsa_init);
