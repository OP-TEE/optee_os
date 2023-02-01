// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022.
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <initcall.h>
#include <ipi.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

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
	struct versal_cmd_args arg = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_PKCS_V1_5:
		return sw_crypto_acipher_rsaes_encrypt(rsa_data->algo,
						rsa_data->key.key,
						rsa_data->label.data,
						rsa_data->label.length,
						rsa_data->message.data,
						rsa_data->message.length,
						rsa_data->cipher.data,
						&rsa_data->cipher.length);
	case DRVCRYPT_RSA_OAEP:
		return sw_crypto_acipher_rsaes_encrypt(rsa_data->algo,
						rsa_data->key.key,
						rsa_data->label.data,
						rsa_data->label.length,
						rsa_data->message.data,
						rsa_data->message.length,
						rsa_data->cipher.data,
						&rsa_data->cipher.length);
	case DRVCRYPT_RSA_NOPAD:
		return sw_crypto_acipher_rsanopad_encrypt(rsa_data->key.key,
						rsa_data->message.data,
						rsa_data->message.length,
						rsa_data->cipher.data,
						&rsa_data->cipher.length);
	case DRVCRYPT_RSASSA_PKCS_V1_5:
		assert(rsa_data->hash_algo != TEE_ALG_SHA1);
		assert(rsa_data->key.n_size != 128);
		break;
	case DRVCRYPT_RSASSA_PSS:
	default:
		assert(0);
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

	if (versal_crypto_request(VERSAL_RSA_PUBLIC_ENCRYPT, &arg, &err)) {
		EMSG("Versal RSA: encrypt: error 0x%x [id:0x%x, len:%zu]",
		     err, rsa_data->rsa_id, rsa_data->key.n_size);

		if (rsa_data->rsa_id == DRVCRYPT_RSASSA_PKCS_V1_5)
			ret = TEE_ERROR_SIGNATURE_INVALID;
		else
			ret = TEE_ERROR_GENERIC;
	}

	if (!ret) {
		rsa_data->cipher.length = rsa_data->key.n_size;
		memcpy(rsa_data->cipher.data, cipher.buf, rsa_data->key.n_size);
	}

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
	struct versal_cmd_args arg = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_PKCS_V1_5:
		return sw_crypto_acipher_rsaes_decrypt(rsa_data->algo,
						rsa_data->key.key,
						rsa_data->label.data,
						rsa_data->label.length,
						rsa_data->cipher.data,
						rsa_data->cipher.length,
						rsa_data->message.data,
						&rsa_data->message.length);
	case DRVCRYPT_RSA_OAEP:
		return sw_crypto_acipher_rsaes_decrypt(rsa_data->algo,
						rsa_data->key.key,
						rsa_data->label.data,
						rsa_data->label.length,
						rsa_data->cipher.data,
						rsa_data->cipher.length,
						rsa_data->message.data,
						&rsa_data->message.length);
	case DRVCRYPT_RSA_NOPAD:
		return sw_crypto_acipher_rsanopad_decrypt(rsa_data->key.key,
						rsa_data->cipher.data,
						rsa_data->cipher.length,
						rsa_data->message.data,
						&rsa_data->message.length);
	case DRVCRYPT_RSASSA_PKCS_V1_5:
		assert(rsa_data->hash_algo != TEE_ALG_SHA1);
		assert(rsa_data->key.n_size != 128);
		break;
	case DRVCRYPT_RSASSA_PSS:
	default:
		assert(0);
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

	if (versal_crypto_request(VERSAL_RSA_PRIVATE_DECRYPT, &arg, &err)) {
		EMSG("Versal RSA: decrypt: error 0x%x [id:0x%x, len:%zu]",
		     err, rsa_data->rsa_id, rsa_data->key.n_size);
		ret = TEE_ERROR_GENERIC;
	}

	if (!ret) {
		rsa_data->message.length = rsa_data->key.n_size;
		memcpy(rsa_data->message.data, msg.buf, rsa_data->key.n_size);
	}

	free(cipher.buf);
	free(cmd);
	free(key.buf);
	free(msg.buf);

	return ret;
}

static TEE_Result do_ssa_sign(struct drvcrypt_rsa_ssa *p)
{
	switch (p->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		if (p->key.n_size != 128) {
			/* use DRVCRYPT_RSASSA_PKCS_V1_5, decrypt */
			return TEE_ERROR_NOT_IMPLEMENTED;
		}
		return sw_crypto_acipher_rsassa_sign(p->algo,
						     p->key.key,
						     p->salt_len,
						     p->message.data,
						     p->message.length,
						     p->signature.data,
						     &p->signature.length);
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		return sw_crypto_acipher_rsassa_sign(p->algo,
						     p->key.key,
						     p->salt_len,
						     p->message.data,
						     p->message.length,
						     p->signature.data,
						     &p->signature.length);
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return sw_crypto_acipher_rsassa_sign(p->algo,
						     p->key.key,
						     p->salt_len,
						     p->message.data,
						     p->message.length,
						     p->signature.data,
						     &p->signature.length);
	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result do_ssa_verify(struct drvcrypt_rsa_ssa *p)
{
	switch (p->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		if (p->key.n_size != 128) {
			/* use DRVCRYPT_RSASSA_PKCS_V1_5, encrypt */
			return TEE_ERROR_NOT_IMPLEMENTED;
		}
		return sw_crypto_acipher_rsassa_verify(p->algo,
						       p->key.key,
						       p->salt_len,
						       p->message.data,
						       p->message.length,
						       p->signature.data,
						       p->signature.length);
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		return sw_crypto_acipher_rsassa_verify(p->algo,
						       p->key.key,
						       p->salt_len,
						       p->message.data,
						       p->message.length,
						       p->signature.data,
						       p->signature.length);
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return sw_crypto_acipher_rsassa_verify(p->algo,
						       p->key.key,
						       p->salt_len,
						       p->message.data,
						       p->message.length,
						       p->signature.data,
						       p->signature.length);
	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result do_gen_keypair(struct rsa_keypair *s, size_t size_bits)
{
	return sw_crypto_acipher_gen_rsa_key(s, size_bits);
}

static TEE_Result do_alloc_keypair(struct rsa_keypair *s, size_t size_bits)
{
	return sw_crypto_acipher_alloc_rsa_keypair(s, size_bits);
}

static TEE_Result do_alloc_publickey(struct rsa_public_key *key, size_t bits)
{
	return sw_crypto_acipher_alloc_rsa_public_key(key, bits);
}

static void do_free_publickey(struct rsa_public_key *s)
{
	sw_crypto_acipher_free_rsa_public_key(s);
}

static void do_free_keypair(struct rsa_keypair *s)
{
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
	struct versal_cmd_args arg = { };

	if (versal_crypto_request(VERSAL_RSA_KAT, &arg, NULL))
		return TEE_ERROR_GENERIC;

	return drvcrypt_register_rsa(&driver_rsa);
}

driver_init(rsa_init);
