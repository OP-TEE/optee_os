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
#include <tee/tee_cryp_utl.h>

#include "ipi.h"

/* Xilinx Versal Known Answer Tests */
#define XSECURE_ECDSA_KAT_NIST_P384	0
#define XSECURE_ECDSA_KAT_NIST_P521	2

#define __STR(X) #X
#define STR(X) __STR(X)

static const struct crypto_ecc_keypair_ops *keypair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

enum versal_ecc_err {
	KAT_KEY_NOTVALID_ERROR = 0xC0,
	KAT_FAILED_ERROR,
	NON_SUPPORTED_CURVE,
	KEY_ZERO,
	KEY_WRONG_ORDER,
	KEY_NOT_ON_CURVE,
	BAD_SIGN,
	GEN_SIGN_INCORRECT_HASH_LEN,
	VER_SIGN_INCORRECT_HASH_LEN,
	GEN_SIGN_BAD_RAND_NUM,
	GEN_KEY_ERR,
	INVALID_PARAM,
	VER_SIGN_R_ZERO,
	VER_SIGN_S_ZERO,
	VER_SIGN_R_ORDER_ERROR,
	VER_SIGN_S_ORDER_ERROR,
	KAT_INVLD_CRV_ERROR,
};

static const char *versal_ecc_error(uint8_t err)
{
	struct {
		enum versal_ecc_err error;
		const char *name;
	} elist[] = {
		{ KAT_KEY_NOTVALID_ERROR, STR(KAT_KEY_NOTVALID_ERROR), },
		{ KAT_FAILED_ERROR, STR(KAT_FAILED_ERROR), },
		{ NON_SUPPORTED_CURVE, STR(NON_SUPPORTED_CURVE), },
		{ KEY_ZERO, STR(KEY_ZERO), },
		{ KEY_WRONG_ORDER, STR(KEY_WRONG_ORDER), },
		{ KEY_NOT_ON_CURVE, STR(KEY_NOT_ON_CURVE), },
		{ BAD_SIGN, STR(BAD_SIGN), },
		{ GEN_SIGN_INCORRECT_HASH_LEN,
			STR(GEN_SIGN_INCORRECT_HASH_LEN), },
		{ VER_SIGN_INCORRECT_HASH_LEN,
			STR(VER_SIGN_INCORRECT_HASH_LEN), },
		{ GEN_SIGN_BAD_RAND_NUM, STR(GEN_SIGN_BAD_RAND_NUM), },
		{ GEN_KEY_ERR, STR(GEN_KEY_ERR), },
		{ INVALID_PARAM, STR(INVALID_PARAM), },
		{ VER_SIGN_R_ZERO, STR(VER_SIGN_R_ZERO), },
		{ VER_SIGN_S_ZERO, STR(VER_SIGN_S_ZERO), },
		{ VER_SIGN_R_ORDER_ERROR, STR(VER_SIGN_R_ORDER_ERROR), },
		{ VER_SIGN_S_ORDER_ERROR, STR(VER_SIGN_S_ORDER_ERROR), },
		{ KAT_INVLD_CRV_ERROR, STR(KAT_INVLD_CRV_ERROR), },
	};

	if (err <= KAT_INVLD_CRV_ERROR && err >= KAT_KEY_NOTVALID_ERROR) {
		if (elist[err - KAT_KEY_NOTVALID_ERROR].name)
			return elist[err - KAT_KEY_NOTVALID_ERROR].name;

		return "Invalid";
	}

	return "Unknown";
}

static TEE_Result ecc_get_key_size(uint32_t curve, size_t *bytes, size_t *bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P384:
		*bits = 384;
		*bytes = 48;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*bits = 521;
		*bytes = 66;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static void crypto_bignum_bn2bin_eswap(uint32_t curve,
				       struct bignum *from, uint8_t *to)
{
	uint8_t pad[66] = { 0 };
	uint8_t tmp = 0;
	size_t i = 0;
	size_t j = 0;
	size_t len = crypto_bignum_num_bytes(from);
	size_t bytes = 0;
	size_t bits = 0;

	if (ecc_get_key_size(curve, &bytes, &bits))
		panic();

	crypto_bignum_bn2bin(from, pad + bytes - len);
	for (i = 0, j = bytes - 1; i < j; i++, j--) {
		tmp = pad[i];
		pad[i] = pad[j];
		pad[j] = tmp;
	}
	memcpy(to, pad, bytes);
}

static TEE_Result ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
				  size_t msg_len, struct versal_mbox_mem *p)
{
	uint8_t buf[TEE_SHA512_HASH_SIZE + 2] = { 0 };
	size_t len = 0;

	switch (algo) {
	case TEE_ALG_ECDSA_P384:
		len = TEE_SHA384_HASH_SIZE;
		if (msg_len == TEE_SHA384_HASH_SIZE)
			break;

		if (tee_hash_createdigest(TEE_ALG_SHA384, msg, msg_len,
					  buf, sizeof(buf)))
			panic();
		break;
	case TEE_ALG_ECDSA_P521:
		len = TEE_SHA512_HASH_SIZE + 2;
		if (msg_len == TEE_SHA512_HASH_SIZE + 2)
			break;

		if (tee_hash_createdigest(TEE_ALG_SHA512, msg, msg_len,
					  buf, sizeof(buf)))
			panic();
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	/* write the hash - or msg - to the message buffer */
	versal_mbox_alloc(len, msg_len == len ? msg : buf, p);

	return TEE_SUCCESS;
}

static TEE_Result verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_len,
			 const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ecc_verify_param *cmd = NULL;
	struct versal_mbox_mem x = { };
	struct versal_mbox_mem s = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem cmd_buf = { };
	struct cmd_args arg = { };
	uint32_t err = 0;
	size_t bytes = 0;
	size_t bits = 0;

	ret = ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret != TEE_SUCCESS) {
		if (ret != TEE_ERROR_NOT_SUPPORTED)
			return ret;

		return pub_ops->verify(algo, key, msg, msg_len, sig, sig_len);
	}

	ret = ecc_prepare_msg(algo, msg, msg_len, &p);
	if (ret)
		return ret;

	versal_mbox_alloc(bytes * 2, NULL, &x);
	crypto_bignum_bn2bin_eswap(key->curve, key->x, x.buf);
	crypto_bignum_bn2bin_eswap(key->curve, key->y,
				   (uint8_t *)x.buf + bytes);
	/* Validate the public key for the curve */
	arg.data[0] = key->curve;
	arg.dlen = 1;
	arg.ibuf[0].mem = x;
	if (versal_crypto_request(ELLIPTIC_VALIDATE_PUBLIC_KEY, &arg, &err)) {
		EMSG("Versal ECC: %s", versal_ecc_error(err));
		ret = TEE_ERROR_GENERIC;
		goto out;
	}
	memset(&arg, 0, sizeof(arg));

	/* Verify the message with the validated key */
	versal_mbox_alloc(sig_len, sig, &s);
	versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);

	cmd = cmd_buf.buf;
	cmd->signature_addr = virt_to_phys(s.buf);
	cmd->pub_key_addr = virt_to_phys(x.buf);
	cmd->hash_addr = virt_to_phys(p.buf);
	cmd->hash_len = p.len;
	cmd->curve = key->curve;

	arg.ibuf[0].mem = cmd_buf;
	arg.ibuf[1].mem = p;
	arg.ibuf[1].only_cache = true;
	arg.ibuf[2].mem = x;
	arg.ibuf[3].mem = s;

	if (versal_crypto_request(ELLIPTIC_VERIFY_SIGN, &arg, &err)) {
		EMSG("Versal ECC: %s", versal_ecc_error(err));
		ret = TEE_ERROR_GENERIC;
	}
out:
	free(p.buf);
	free(x.buf);
	free(s.buf);
	free(cmd);

	return ret;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	struct versal_ecc_sign_param *cmd = NULL;
	struct versal_mbox_mem cmd_buf = { };
	struct ecc_keypair ephemeral = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem k = { };
	struct versal_mbox_mem d = { };
	struct versal_mbox_mem s = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	uint32_t err = 0;
	size_t bytes = 0;
	size_t bits = 0;

	ret = ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret != TEE_SUCCESS) {
		if (ret != TEE_ERROR_NOT_SUPPORTED)
			return ret;

		return keypair_ops->sign(algo, key, msg, msg_len, sig, sig_len);
	}

	/* Hash and update the length */
	ret = ecc_prepare_msg(algo, msg, msg_len, &p);
	if (ret)
		panic();

	/* Ephemeral private key */
	ret = drvcrypt_asym_alloc_ecc_keypair(&ephemeral,
					      TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		EMSG("Versal, can't allocate the ephemeral key");
		return ret;
	}

	ephemeral.curve = key->curve;
	ret = crypto_acipher_gen_ecc_key(&ephemeral, bits);
	if (ret) {
		EMSG("Versal, can't generate the ephemeral key");
		return ret;
	}

	versal_mbox_alloc(bytes, NULL, &k);
	crypto_bignum_bn2bin_eswap(key->curve, ephemeral.d, k.buf);
	crypto_bignum_free(ephemeral.d);
	crypto_bignum_free(ephemeral.x);
	crypto_bignum_free(ephemeral.y);

	/* Private key*/
	versal_mbox_alloc(bytes, NULL, &d);
	crypto_bignum_bn2bin_eswap(key->curve, key->d, d.buf);

	/* Signature */
	versal_mbox_alloc(*sig_len, NULL, &s);

	/* IPI command */
	versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);

	cmd = cmd_buf.buf;
	cmd->priv_key_addr = virt_to_phys(d.buf);
	cmd->epriv_key_addr = virt_to_phys(k.buf);
	cmd->hash_addr = virt_to_phys(p.buf);
	cmd->hash_len = p.len;
	cmd->curve = key->curve;

	arg.ibuf[0].mem = cmd_buf;
	arg.ibuf[1].mem = s;
	arg.ibuf[2].mem = k;
	arg.ibuf[3].mem = d;
	arg.ibuf[4].mem = p;

	if (versal_crypto_request(ELLIPTIC_GENERATE_SIGN, &arg, &err)) {
		EMSG("Versal ECC: %s", versal_ecc_error(err));
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	*sig_len = 2 * bytes;
	memcpy(sig, s.buf, *sig_len);
out:
	free(cmd);
	free(k.buf);
	free(p.buf);
	free(s.buf);
	free(d.buf);

	return ret;
}

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	return keypair_ops->shared_secret(private_key, public_key,
					       secret, secret_len);
}

static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	return shared_secret(sdata->key_priv,
			     sdata->key_pub,
			     sdata->secret.data,
			     &sdata->secret.length);
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	return sign(sdata->algo,
		    sdata->key,
		    sdata->message.data,
		    sdata->message.length,
		    sdata->signature.data,
		    &sdata->signature.length);
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	return verify(sdata->algo,
		      sdata->key,
		      sdata->message.data,
		      sdata->message.length,
		      sdata->signature.data,
		      sdata->signature.length);
}

static TEE_Result do_gen_keypair(struct ecc_keypair *s, size_t size_bits)
{
	/* Versal requires little endian so need to eswap on Versal IP ops.
	 * We chose not to do it here because some tests might be using
	 * their own keys
	 */
	return keypair_ops->generate(s, size_bits);
}

static TEE_Result do_alloc_keypair(struct ecc_keypair *s, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = crypto_asym_alloc_ecc_keypair(s, TEE_TYPE_ECDSA_KEYPAIR,
					    size_bits);
	if (ret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	s->ops = NULL;

	return TEE_SUCCESS;
}

static TEE_Result do_alloc_publickey(struct ecc_public_key *s, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = crypto_asym_alloc_ecc_public_key(s, TEE_TYPE_ECDSA_PUBLIC_KEY,
					       size_bits);
	if (ret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	s->ops = NULL;

	return TEE_SUCCESS;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	return pub_ops->free(s);
}

static struct drvcrypt_ecc driver_ecc = {
	.shared_secret = do_shared_secret,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.alloc_keypair = do_alloc_keypair,
	.gen_keypair = do_gen_keypair,
	.verify = do_verify,
	.sign = do_sign,
};

static TEE_Result ecc_init(void)
{
	struct cmd_args arg = { };
	uint32_t err = 0;

	arg.data[arg.dlen++] = XSECURE_ECDSA_KAT_NIST_P384;
	if (versal_crypto_request(ELLIPTIC_KAT, &arg, &err)) {
		EMSG("Versal KAG NIST_P384: %s", versal_ecc_error(err));
		return TEE_ERROR_GENERIC;
	}

	/* clean previous request */
	arg.dlen = 0;

	arg.data[arg.dlen++] = XSECURE_ECDSA_KAT_NIST_P521;
	if (versal_crypto_request(ELLIPTIC_KAT, &arg, &err)) {
		EMSG("Versal KAG NIST_P521 %s", versal_ecc_error(err));
		return TEE_ERROR_GENERIC;
	}

	keypair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!keypair_ops)
		return TEE_ERROR_GENERIC;

	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	return drvcrypt_register_ecc(&driver_ecc);
}

driver_init(ecc_init);
