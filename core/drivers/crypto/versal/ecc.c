// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022.
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <config.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <ecc.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>

/* Software based ECDSA operations */
static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

TEE_Result versal_ecc_get_key_size(uint32_t curve, size_t *bytes, size_t *bits)
{
	switch (curve) {
#if defined(CFG_VERSAL_PKI_DRIVER)
	case TEE_ECC_CURVE_NIST_P256:
		*bits = 256;
		*bytes = 32;
		break;
#endif
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

void versal_memcpy_swp(uint8_t *to, const uint8_t *from, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		to[i] = from[len - 1 - i];
}

void versal_crypto_bignum_bn2bin_eswap(uint32_t curve, struct bignum *from,
				       uint8_t *to)
{
	uint8_t pad[66] = { 0 };
	size_t len = crypto_bignum_num_bytes(from);
	size_t bytes = 0;
	size_t bits = 0;

	if (versal_ecc_get_key_size(curve, &bytes, &bits))
		panic();

	crypto_bignum_bn2bin(from, pad + bytes - len);
	versal_memcpy_swp(to, pad, bytes);
}

void versal_crypto_bignum_bin2bn_eswap(const uint8_t *from, size_t sz,
				       struct bignum *to)
{
	uint8_t pad[66] = { 0 };

	assert(sz <= sizeof(pad));

	versal_memcpy_swp(pad, from, sz);
	crypto_bignum_bin2bn(pad, sz, to);
}

TEE_Result versal_ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
				  size_t msg_len, size_t *len, uint8_t *buf)
{
	if (msg_len > TEE_SHA512_HASH_SIZE + 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (algo == TEE_ALG_ECDSA_SHA384)
		*len = TEE_SHA384_HASH_SIZE;
	else if (algo == TEE_ALG_ECDSA_SHA512)
		*len = TEE_SHA512_HASH_SIZE + 2;
#if defined(PLATFORM_FLAVOR_net)
	else if (algo == TEE_ALG_ECDSA_SHA256)
		*len = TEE_SHA256_HASH_SIZE;
#endif
	else
		return TEE_ERROR_NOT_SUPPORTED;

	/* Swap the hash/message and pad if necessary */
	versal_memcpy_swp(buf, msg, msg_len);

	return TEE_SUCCESS;
}

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
	TEE_Result ret = versal_ecc_gen_keypair(s);

	if (ret == TEE_ERROR_NOT_SUPPORTED)
		return pair_ops->generate(s, size_bits);

#ifdef CFG_VERSAL_PKI_PWCT
	if (ret != TEE_SUCCESS)
		return ret;

	/* Perform a pairwise consistencty test on the generated key pair */
	ret = versal_ecc_keypair_pwct(s);
	if (ret)
		DMSG("Pair-wise consistency test failed (0x%" PRIx32 ")", ret);
#endif

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
	if (ret != TEE_SUCCESS)
		return ret;

	/* Run KAT self-tests */
	ret = versal_ecc_kat_test();
	if (ret != TEE_SUCCESS)
		return ret;

	/* Fall back to software implementations if needed */
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
