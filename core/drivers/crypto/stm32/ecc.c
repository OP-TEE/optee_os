// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <initcall.h>
#include <stdlib_ext.h>
#include <string.h>
#include <tee_api_types.h>

#include "common.h"
#include "stm32_pka.h"

static TEE_Result algo_to_pka_cid(uint32_t algo,
				  enum stm32_pka_curve_id *cid)
{
	switch (algo) {
	case TEE_ALG_ECDSA_P192:
		*cid = PKA_NIST_P192;
		break;
	case TEE_ALG_ECDSA_P224:
		*cid = PKA_NIST_P224;
		break;
	case TEE_ALG_ECDSA_P256:
		*cid = PKA_NIST_P256;
		break;
	case TEE_ALG_ECDSA_P384:
		*cid = PKA_NIST_P384;
		break;
	case TEE_ALG_ECDSA_P521:
		*cid = PKA_NIST_P521;
		break;
	default:
		EMSG("algorithm %#"PRIx32" not enabled", algo);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result curve_to_pka_cid(uint32_t curve,
				   enum stm32_pka_curve_id *cid)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*cid = PKA_NIST_P192;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*cid = PKA_NIST_P224;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*cid = PKA_NIST_P256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*cid = PKA_NIST_P384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*cid = PKA_NIST_P521;
		break;
	default:
		EMSG("curve %#"PRIx32" not enabled", curve);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_gen_keypair(struct ecc_keypair *key, size_t size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_pka_bn d = { };
	struct stm32_pka_point pk = { };
	enum stm32_pka_curve_id cid = PKA_LAST_CID;
	size_t bytes = 0;

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("Using PKA");
	res = curve_to_pka_cid(key->curve, &cid);
	if (res)
		return res;

	res = stm32_pka_get_max_size(&bytes, NULL, cid);
	if (res)
		return res;

	if (size_bits > bytes * 8 ||
	    crypto_bignum_num_bytes(key->d) > bytes ||
	    crypto_bignum_num_bytes(key->x) > bytes ||
	    crypto_bignum_num_bytes(key->y) > bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	d.val = calloc(1, bytes);
	d.size = bytes;
	if (!d.val)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Private key is a random vector */
	res = crypto_rng_read(d.val, d.size);
	if (res) {
		free(d.val);
		return res;
	}

	pk.x.val = calloc(1, bytes);
	pk.x.size = bytes;
	if (!pk.x.val) {
		free(d.val);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	pk.y.val = calloc(1, bytes);
	pk.y.size = bytes;
	if (!pk.y.val) {
		free(pk.x.val);
		free(d.val);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = stm32_pka_edac_gen_pubkey(&d, &pk, cid);
	if (res)
		goto out;

	res = crypto_bignum_bin2bn(d.val, d.size, key->d);
	if (res)
		goto out;

	res = crypto_bignum_bin2bn(pk.x.val, pk.x.size, key->x);
	if (res)
		goto out;

	res = crypto_bignum_bin2bn(pk.y.val, pk.y.size, key->y);

out:
	free(pk.y.val);
	free(pk.x.val);
	free_wipe(d.val);

	return res;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_size,
		       uint8_t *sig, size_t *sig_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum stm32_pka_curve_id cid_from_algo = PKA_LAST_CID;
	enum stm32_pka_curve_id cid = PKA_LAST_CID;
	struct stm32_pka_bn d = { };
	struct stm32_pka_bn k = { };
	struct stm32_pka_bn sig_r = { };
	struct stm32_pka_bn sig_s = { };
	size_t bytes = 0;

	if (!key || !msg || !sig || !sig_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (curve_to_pka_cid(key->curve, &cid) ||
	    algo_to_pka_cid(algo, &cid_from_algo) ||
	    cid_from_algo != cid)
		return TEE_ERROR_BAD_PARAMETERS;

	res = stm32_pka_get_max_size(&bytes, NULL, cid);
	if (res)
		return res;

	if (crypto_bignum_num_bytes(key->d) > bytes || *sig_len < 2 * bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	*sig_len = 2 * bytes;

	d.size = crypto_bignum_num_bytes(key->d);
	d.val = calloc(1, d.size);
	if (!d.val)
		return TEE_ERROR_OUT_OF_MEMORY;

	crypto_bignum_bn2bin(key->d, d.val);

	k.val = calloc(1, bytes);
	k.size = bytes;
	if (!k.val) {
		free_wipe(d.val);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = crypto_rng_read(k.val, k.size);
	if (res)
		goto out;

	sig_r.val = (void *)sig;
	sig_r.size = bytes;
	sig_s.val = (void *)(sig + bytes);
	sig_s.size = bytes;

	res = stm32_pka_ecdsa_sign(msg, msg_size, &sig_r, &sig_s, &d, &k, cid);

out:
	free_wipe(k.val);
	free_wipe(d.val);

	return res;
}

static TEE_Result stm32_sign(struct drvcrypt_sign_data *sdata)
{
	if (!sdata)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("Using PKA");
	return sign(sdata->algo,
		    sdata->key,
		    sdata->message.data,
		    sdata->message.length,
		    sdata->signature.data,
		    &sdata->signature.length);
}

static TEE_Result verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_size,
			 const uint8_t *sig, size_t sig_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_pka_bn sig_r = { };
	struct stm32_pka_bn sig_s = { };
	struct stm32_pka_point pk = { };
	enum stm32_pka_curve_id cid_from_algo = PKA_LAST_CID;
	enum stm32_pka_curve_id cid = PKA_LAST_CID;
	size_t bytes = 0;

	if (!key || !msg || !sig)
		return TEE_ERROR_BAD_PARAMETERS;

	if (curve_to_pka_cid(key->curve, &cid) ||
	    algo_to_pka_cid(algo, &cid_from_algo) ||
	    cid_from_algo != cid)
		return TEE_ERROR_BAD_PARAMETERS;

	res = stm32_pka_get_max_size(&bytes, NULL, cid);
	if (res)
		return res;

	if (sig_size % 2)
		return TEE_ERROR_BAD_PARAMETERS;

	sig_r.val = (void *)sig;
	sig_r.size = sig_size / 2;
	sig_s.val = (void *)(sig + sig_size / 2);
	sig_s.size = sig_size / 2;

	pk.x.size = crypto_bignum_num_bytes(key->x);
	pk.x.val = calloc(1, pk.x.size);
	if (!pk.x.val)
		return TEE_ERROR_OUT_OF_MEMORY;

	crypto_bignum_bn2bin(key->x, pk.x.val);

	pk.y.size = crypto_bignum_num_bytes(key->y);
	pk.y.val = calloc(1, pk.y.size);
	if (!pk.y.val) {
		free(pk.x.val);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	crypto_bignum_bn2bin(key->y, pk.y.val);

	res = stm32_pka_ecdsa_verif(msg, msg_size, &sig_r, &sig_s, &pk, cid);

	free(pk.y.val);
	free(pk.x.val);

	return res;
}

static TEE_Result stm32_verify(struct drvcrypt_sign_data *sdata)
{
	if (!sdata)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("Using PKA");
	return verify(sdata->algo,
		      sdata->key,
		      sdata->message.data,
		      sdata->message.length,
		      sdata->signature.data,
		      sdata->signature.length);
}

static TEE_Result stm32_alloc_keypair(struct ecc_keypair *s, uint32_t type,
				      size_t size_bits __unused)
{
	if (!s)
		return TEE_ERROR_BAD_PARAMETERS;

	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_KEYPAIR &&
	    type != TEE_TYPE_ECDH_KEYPAIR)
		return TEE_ERROR_NOT_IMPLEMENTED;

	FMSG("Using PKA");
	memset(s, 0, sizeof(*s));

	s->d = crypto_bignum_allocate(PKA_MAX_ECC_LEN);
	if (!s->d)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->x = crypto_bignum_allocate(PKA_MAX_ECC_LEN);
	if (!s->x) {
		crypto_bignum_free(&s->d);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	s->y = crypto_bignum_allocate(PKA_MAX_ECC_LEN);
	if (!s->y) {
		crypto_bignum_free(&s->d);
		crypto_bignum_free(&s->x);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_alloc_publickey(struct ecc_public_key *s, uint32_t type,
					size_t size_bits __unused)
{
	if (!s)
		return TEE_ERROR_BAD_PARAMETERS;

	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_PUBLIC_KEY &&
	    type != TEE_TYPE_ECDH_PUBLIC_KEY)
		return TEE_ERROR_NOT_IMPLEMENTED;

	memset(s, 0, sizeof(*s));

	s->x = crypto_bignum_allocate(PKA_MAX_ECC_LEN);
	if (!s->x)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->y = crypto_bignum_allocate(PKA_MAX_ECC_LEN);
	if (!s->y) {
		crypto_bignum_free(&s->x);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

static void stm32_free_publickey(struct ecc_public_key *s)
{
	if (!s)
		return;

	FMSG("Using PKA");
	crypto_bignum_free(&s->x);
	crypto_bignum_free(&s->y);
}

static TEE_Result is_point_on_curve(struct stm32_pka_point *point,
				    enum stm32_pka_curve_id cid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_pka_bn r2modn = { };

	res = stm32_pka_get_max_size(&r2modn.size, NULL, cid);
	if (res)
		return res;

	r2modn.val = calloc(1, r2modn.size);
	if (!r2modn.val)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = stm32_pka_ecc_compute_montgomery(&r2modn, cid);
	if (res)
		goto out;

	res = stm32_pka_is_point_on_curve(point, &r2modn, cid);
out:
	free(r2modn.val);

	return res;
}

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum stm32_pka_curve_id cid = PKA_LAST_CID;
	struct stm32_pka_bn d = { };
	struct stm32_pka_point pk = { };
	struct stm32_pka_point result = { };
	size_t bytes = 0;

	if (!private_key || !public_key || !secret || !secret_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (private_key->curve != public_key->curve ||
	    curve_to_pka_cid(public_key->curve, &cid))
		return TEE_ERROR_BAD_PARAMETERS;

	res = stm32_pka_get_max_size(&bytes, NULL, cid);
	if (res)
		return res;

	/* Convert provided value to PKA format */
	pk.x.size = crypto_bignum_num_bytes(public_key->x);
	pk.x.val = calloc(1, pk.x.size);
	if (!pk.x.val)
		return TEE_ERROR_OUT_OF_MEMORY;

	crypto_bignum_bn2bin(public_key->x, pk.x.val);

	pk.y.size = crypto_bignum_num_bytes(public_key->y);
	pk.y.val = calloc(1, pk.y.size);
	if (!pk.y.val) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	crypto_bignum_bn2bin(public_key->y, pk.y.val);

	d.size = crypto_bignum_num_bytes(private_key->d);
	d.val = calloc(1, d.size);
	if (!d.val) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	crypto_bignum_bn2bin(private_key->d, d.val);

	/* Allocate intermediate point */
	result.x.size = bytes;
	result.x.val = calloc(1, result.x.size);
	if (!result.x.val) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	result.y.size = bytes;
	result.y.val = calloc(1, result.y.size);
	if (!result.y.val) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * We should check that provided public_key point is on the selected
	 * curve.
	 */
	res = is_point_on_curve(&pk, cid);
	if (res)
		goto out;

	res = stm32_pka_ecc_scalar_mul(&d, &pk, &result, cid);
	if (res)
		goto out;

	if (*secret_len < result.x.size) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	memcpy(secret, result.x.val, result.x.size);
	*secret_len = result.x.size;
out:
	free_wipe(result.y.val);
	free_wipe(result.x.val);
	free_wipe(d.val);
	free(pk.y.val);
	free(pk.x.val);

	return res;
}

static TEE_Result stm32_shared_secret(struct drvcrypt_secret_data *sdata)
{
	if (!sdata)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("Using PKA");
	return shared_secret(sdata->key_priv,
			     sdata->key_pub,
			     sdata->secret.data,
			     &sdata->secret.length);
}

/*
 * Registration of the ECC Driver.
 */
static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = stm32_alloc_keypair,
	.alloc_publickey = stm32_alloc_publickey,
	.free_publickey = stm32_free_publickey,
	.gen_keypair = stm32_gen_keypair,
	.sign = stm32_sign,
	.verify = stm32_verify,
	.shared_secret = stm32_shared_secret,
};

TEE_Result stm32_register_ecc(void)
{
	return drvcrypt_register_ecc(&driver_ecc);
}
