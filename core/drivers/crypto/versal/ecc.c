// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022.
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <ecc.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>

/* Software based ECDSA operations */
static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	return pair_ops->shared_secret(private_key, public_key,
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
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_ecc_sign(sdata->algo,
			      sdata->key,
			      sdata->message.data,
			      sdata->message.length,
			      sdata->signature.data,
			      &sdata->signature.length);

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		/* Fallback to software */
		return pair_ops->sign(sdata->algo, sdata->key,
				      sdata->message.data,
				      sdata->message.length,
				      sdata->signature.data,
				      &sdata->signature.length);
	}

	return ret;
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_ecc_verify(sdata->algo,
				sdata->key,
				sdata->message.data,
				sdata->message.length,
				sdata->signature.data,
				sdata->signature.length);

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		/* Fallback to software */
		return pub_ops->verify(sdata->algo, sdata->key,
				       sdata->message.data,
				       sdata->message.length,
				       sdata->signature.data,
				       sdata->signature.length);
	}

	return ret;
}

static TEE_Result do_gen_keypair(struct ecc_keypair *s, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	/*
	 * Versal requires little endian so need to versal_memcpy_swp on Versal
	 * IP ops. We chose not to do it here because some tests might be using
	 * their own keys
	 */
	ret = versal_ecc_gen_keypair(s);

	if (ret == TEE_ERROR_NOT_SUPPORTED)
		/* Fallback to software */
		return pair_ops->generate(s, size_bits);

	return ret;
}

static TEE_Result do_alloc_keypair(struct ecc_keypair *s,
				   uint32_t type, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_KEYPAIR &&
	    type != TEE_TYPE_ECDH_KEYPAIR)
		return TEE_ERROR_NOT_IMPLEMENTED;

	ret = crypto_asym_alloc_ecc_keypair(s, TEE_TYPE_ECDSA_KEYPAIR,
					    size_bits);
	if (ret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/*
	 * Ignore the software operations, the crypto API will populate
	 * this interface.
	 */
	s->ops = NULL;

	return TEE_SUCCESS;
}

static TEE_Result do_alloc_publickey(struct ecc_public_key *s,
				     uint32_t type, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_PUBLIC_KEY &&
	    type != TEE_TYPE_ECDH_PUBLIC_KEY)
		return TEE_ERROR_NOT_IMPLEMENTED;

	ret = crypto_asym_alloc_ecc_public_key(s, TEE_TYPE_ECDSA_PUBLIC_KEY,
					       size_bits);
	if (ret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/*
	 * Ignore the software operations, the crypto API will populate
	 * this interface.
	 */
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
	TEE_Result ret = TEE_SUCCESS;

	/* HW initialization if needed */
	ret = versal_ecc_hw_init();
	if (ret)
		return ret;

	/* Run KAT self-tests */
	ret = versal_ecc_kat_test();
	if (ret)
		return ret;

	/* Initialize fallback to software implementations, if needed later */
	pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!pair_ops)
		return TEE_ERROR_GENERIC;

	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	/* This driver supports both ECDH and ECDSA */
	assert((pub_ops ==
		crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDH_PUBLIC_KEY)) &&
	       (pair_ops ==
		crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDH_KEYPAIR)));

	return drvcrypt_register_ecc(&driver_ecc);
}

driver_init(ecc_init);
