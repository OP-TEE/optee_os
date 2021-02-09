// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#include <compiler.h>
#include <stdio.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <pta_attestation.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>
#include <tee_api_types.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include "attestation.h"

#define RSA_SIG_SIZE_BYTE 256

/*
 * Attestation data is static to keep until the device boots again.
 * Afterwards the attestation data has to be reloaded and everthing
 * has to be attestated newly.
 */
static struct attestation_data {
	uint8_t *iv;
	uint32_t iv_size;
	uint8_t *pub;
	uint32_t pub_size;
	uint8_t *enc_priv;
	uint32_t enc_priv_size;
	uint8_t *sig;
	uint32_t sig_size;
} att_data;

static TEE_Result free_att_data(TEE_Result reason)
{
	att_data.iv_size = 0;
	att_data.pub_size = 0;
	att_data.enc_priv_size = 0;
	att_data.sig_size = 0;

	if (att_data.iv)
		free(att_data.iv);

	if (att_data.pub)
		free(att_data.pub);

	if (att_data.enc_priv)
		free(att_data.enc_priv);

	if (att_data.sig)
		free(att_data.sig);

	return reason;
}

static TEE_Result priv_asn1_decode(uint8_t *priv, const size_t priv_len,
				   uint8_t **d, size_t *d_size)
{
	/* beginn at the start of the modulus (7)*/
	uint32_t offset = 7;
	uint32_t size = 0;

	if (priv_len < offset + 3)
		return TEE_ERROR_SECURITY;

	/* check the header */
	if (priv[0] != 0x30 ||
	    priv[1] != 0x82 ||
	    priv[offset] != 0x02 ||
	    priv[offset + 1] != 0x82)
		return TEE_ERROR_SECURITY;

	/* get the size of the first integer aka modulus */
	size = (priv[offset + 2] << 8) | priv[offset + 3];
	offset += size + 4;

	/* get the size of the second integer aka exponent */
	if (priv[offset] != 0x02)
		return TEE_ERROR_SECURITY;

	size = priv[offset + 1];
	offset += size + 2;

	if (priv_len < offset + 3)
		return TEE_ERROR_SECURITY;

	/* decoding d */
	if (priv[offset] != 0x02 || priv[offset + 1] != 0x82)
		return TEE_ERROR_SECURITY;

	size = (priv[offset + 2] << 8) | priv[offset + 3];

	if (priv_len < offset + 4 + size)
		return TEE_ERROR_SECURITY;

	*d = &priv[offset + 4];
	*d_size = size;

	return TEE_SUCCESS;
}

static TEE_Result pub_asn1_decode(uint8_t **n, uint8_t **e,
				  size_t *n_size, size_t *e_size)
{
	uint32_t size = 0;

	/* Decoding header */
	if (att_data.pub[0] != 0x30 || att_data.pub[1] != 0x82)
		return TEE_ERROR_SECURITY;

	size = (att_data.pub[2] << 8) | att_data.pub[3];
	if ((size + 4) != att_data.pub_size)
		return TEE_ERROR_SECURITY;

	/* Decoding first integer aka modulus */
	if (att_data.pub[4] != 0x02 || att_data.pub[5] != 0x82)
		return TEE_ERROR_SECURITY;

	size = (att_data.pub[6] << 8) | att_data.pub[7];
	*n = &att_data.pub[8];
	*n_size = size;

	/* Decoding second integer aka exponent */
	if (att_data.pub[size + 8] != 0x02)
		return TEE_ERROR_SECURITY;

	*e_size = att_data.pub[size + 9];
	*e = &att_data.pub[size + 10];

	return TEE_SUCCESS;
}

TEE_Result __weak attestation_get_sys_measurement(uint8_t *ptr)
{
	/*
	 * TODO: Dummy function
	 * get_sys_measurement -> do something hardware specific
	 */
	 uint8_t sys[] = {0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00 };
	memcpy(ptr, sys, 32);
	return TEE_SUCCESS;
}

TEE_Result __weak attestation_get_endorsement_key(uint8_t *key)
{
	/*
	 * TODO: Dummy function get_endorsement_key
	 * do something hardware specific
	 */
	uint8_t end_key[] = {0x9a, 0x04, 0xaa, 0x18,
			0x2d, 0x03, 0x96, 0x74,
			0x70, 0x8c, 0xe8, 0x07,
			0xed, 0x91, 0x4c, 0xd1,
			0x53, 0xcd, 0x9d, 0xf7,
			0x80, 0x5e, 0x61, 0x74,
			0x2f, 0x0a, 0xe4, 0x12,
			0x94, 0x75, 0x8d, 0xd3 };
	memcpy(key, end_key, 32);
	return TEE_SUCCESS;
}

TEE_Result __weak attestation_decrypt_priv_key(uint8_t *plain,
					       size_t *plain_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *ctx = NULL;
	size_t block_size = 0;
	uint32_t algo = TEE_ALG_AES_CBC_NOPAD;
	uint32_t mode = TEE_MODE_DECRYPT;
	size_t aes_key_len = TEE_AES_MAX_KEY_SIZE;
	uint8_t endorsement_key[aes_key_len];
	uint8_t *dest_ptr = plain;
	uint8_t *src_ptr = att_data.enc_priv;
	uint32_t enc_size = att_data.enc_priv_size;

	res = crypto_cipher_get_block_size(algo, &block_size);
	if (res)
		goto err;

	if (enc_size % block_size != 0)
		return TEE_ERROR_GENERIC;

	res = attestation_get_endorsement_key(endorsement_key);
	if (res)
		goto err;

	res = crypto_cipher_alloc_ctx(&ctx, algo);
	if (res)
		goto err;

	res = crypto_cipher_init(ctx, mode, endorsement_key,
				 aes_key_len, NULL, 0,
				 att_data.iv, att_data.iv_size);
	if (res)
		goto err;

	for (size_t i = 0; i < enc_size / block_size; i++) {
		res = crypto_cipher_update(ctx, mode, false,
					   src_ptr, block_size, dest_ptr);
		if (res)
			goto err;
		dest_ptr += block_size;
		src_ptr += block_size;
	}

	crypto_cipher_final(ctx);
	*plain_size = enc_size - plain[enc_size - 1];
	res = TEE_SUCCESS;
err:
	crypto_cipher_free_ctx(ctx);
	return res;
}

static TEE_Result get_sha256(uint8_t *dst, uint8_t *src, size_t src_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *ctx = NULL;
	size_t digest_len = TEE_SHA256_HASH_SIZE;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		goto err;

	res = crypto_hash_init(ctx);
	if (res)
		goto err;

	res = crypto_hash_update(ctx, src, src_len);
	if (res)
		goto err;

	res = crypto_hash_final(ctx, dst, digest_len);
	if (res)
		goto err;

	res = TEE_SUCCESS;
err:
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result acipher_sign(const uint8_t *msg, const size_t msg_len,
			       uint8_t *sig, size_t *sig_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rsa_keypair key_pair;
	uint8_t *d_ptr = NULL;
	uint8_t *n_ptr = NULL;
	uint8_t *e_ptr = NULL;
	size_t d_size = 0;
	size_t n_size = 0;
	size_t e_size = 0;
	size_t plain_priv_len = 0;
	uint8_t *plain_priv = calloc(att_data.enc_priv_size, sizeof(uint8_t));

	if (!plain_priv)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = attestation_decrypt_priv_key(plain_priv, &plain_priv_len);
	if (res)
		goto err;

	res = crypto_acipher_alloc_rsa_keypair(&key_pair, 0);
	if (res)
		goto err;

	res = pub_asn1_decode(&n_ptr, &e_ptr, &n_size, &e_size);
	if (res)
		goto err;

	res = priv_asn1_decode(plain_priv, plain_priv_len, &d_ptr, &d_size);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(d_ptr, d_size, key_pair.d);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(e_ptr, e_size, key_pair.e);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(n_ptr, n_size, key_pair.n);
	if (res)
		goto err;

	res = crypto_acipher_rsassa_sign(TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
					 &key_pair,
					 0,	/* salt, default is 20 */
					 msg,
					 msg_len,
					 sig,
					 sig_len);
	if (res)
		goto err;

	res = TEE_SUCCESS;
err:
	free(plain_priv);
	crypto_bignum_free(key_pair.e);
	crypto_bignum_free(key_pair.d);
	crypto_bignum_free(key_pair.n);
	return res;
}

/*
 * encrypt a random number to test the RSA keypair received through the
 * set_data call from the normal world.
 */
static TEE_Result check_attestation_data(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct rsa_keypair key_pair;
	struct rsa_public_key key;
	uint8_t *d_ptr = NULL;
	uint8_t *n_ptr = NULL;
	uint8_t *e_ptr = NULL;
	size_t n_size = 0;
	size_t e_size = 0;
	size_t d_size = 0;

	size_t rn_len = 32;
	size_t enc_rn_len = 0;
	size_t dec_rn_len = 0;
	uint8_t rn[rn_len];
	uint8_t *enc_rn = NULL;
	uint8_t *dec_rn = NULL;

	size_t plain_priv_len = 0;
	uint8_t *plain_priv = calloc(att_data.enc_priv_size, sizeof(uint8_t));

	if (!plain_priv)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* decrypt and decode the encrypted private AIK */
	res = attestation_decrypt_priv_key(plain_priv, &plain_priv_len);
	if (res)
		goto err;

	res = pub_asn1_decode(&n_ptr, &e_ptr, &n_size, &e_size);
	if (res)
		goto err;

	if (!n_ptr || !e_ptr)
		goto err;

	enc_rn_len = n_size;
	enc_rn = calloc(enc_rn_len, sizeof(uint8_t));

	dec_rn_len = n_size + 1;
	dec_rn = calloc(dec_rn_len, sizeof(uint8_t));

	if (!dec_rn || !enc_rn)
		goto err;

	res = crypto_rng_read(rn, rn_len);
	if (res)
		goto err;

	/*
	 * encrypt the random number with
	 * the public attestation identifier key
	 */
	res = crypto_acipher_alloc_rsa_public_key(&key, 0);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(e_ptr, e_size, key.e);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(n_ptr, n_size, key.n);
	if (res)
		goto err;

	res = crypto_acipher_rsaes_encrypt(TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
					   &key,
					   NULL, 0,
					   rn, rn_len,
					   enc_rn, &enc_rn_len);
	if (res)
		goto err;

	/* use the private key to decrypt the random number */
	res = crypto_acipher_alloc_rsa_keypair(&key_pair, 0);
	if (res)
		goto err;

	res = priv_asn1_decode(plain_priv, plain_priv_len, &d_ptr, &d_size);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(d_ptr, d_size, key_pair.d);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(e_ptr, e_size, key_pair.e);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn(n_ptr, n_size, key_pair.n);
	if (res)
		goto err;

	res = crypto_acipher_rsaes_decrypt(TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
					   &key_pair,
					   NULL, 0,
					   enc_rn, enc_rn_len,
					   dec_rn, &dec_rn_len);
	if (res)
		goto err;

	/* validate the decrypted random number vs. the original one */
	for (size_t i = 0; i < dec_rn_len; i++) {
		if (rn[i] != dec_rn[i]) {
			DMSG("%s failed!", __func__);
			goto err;
		}
	}
	res = TEE_SUCCESS;
err:
	crypto_acipher_free_rsa_public_key(&key);
	crypto_bignum_free(key_pair.e);
	crypto_bignum_free(key_pair.d);
	crypto_bignum_free(key_pair.n);
	crypto_bignum_free(key_pair.p);
	crypto_bignum_free(key_pair.q);
	crypto_bignum_free(key_pair.qp);
	crypto_bignum_free(key_pair.dp);
	free(enc_rn);
	free(dec_rn);
	free(plain_priv);
	return res;
}

/*
 * The set data function gets the attestation data from the normal world.
 * This data is verified and saved. The data is device specific and used to
 * forge the attestation certificate.
 */
static TEE_Result set_data(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT);
	if (exp_pt != type)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result res = TEE_ERROR_GENERIC;

	if (att_data.iv_size || att_data.pub_size ||
	    att_data.enc_priv_size || att_data.sig_size)
		return res;

	att_data.iv_size = p[0].memref.size;
	att_data.pub_size = p[1].memref.size;
	att_data.enc_priv_size = p[2].memref.size;
	att_data.sig_size = p[3].memref.size;

	/* allocating the memory for the Attestation data */
	att_data.iv = calloc(att_data.iv_size, sizeof(uint8_t));
	if (!att_data.iv)
		return free_att_data(TEE_ERROR_OUT_OF_MEMORY);

	att_data.pub = calloc(att_data.pub_size, sizeof(uint8_t));
	if (!att_data.pub)
		return free_att_data(TEE_ERROR_OUT_OF_MEMORY);

	att_data.enc_priv = calloc(att_data.enc_priv_size, sizeof(uint8_t));
	if (!att_data.enc_priv)
		return free_att_data(TEE_ERROR_OUT_OF_MEMORY);

	att_data.sig = calloc(att_data.sig_size, sizeof(uint8_t));
	if (!att_data.sig)
		return free_att_data(TEE_ERROR_OUT_OF_MEMORY);

	/* copying all the buffers to the allocated memory */
	memcpy(att_data.iv, p[0].memref.buffer, att_data.iv_size);
	memcpy(att_data.pub, p[1].memref.buffer, att_data.pub_size);
	memcpy(att_data.enc_priv, p[2].memref.buffer, att_data.enc_priv_size);
	memcpy(att_data.sig, p[3].memref.buffer, att_data.sig_size);

	/* check the validity of the received data */
	res = check_attestation_data();
	if (res)
		return free_att_data(res);

	DMSG("Attestation Data has been set!");
	return TEE_SUCCESS;
}

/*
 * This function collects and calculates all the information for the
 * attestation certificate and then forge. Here happens the magic.
 */
static TEE_Result get_cert(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE);
	if (exp_pt != type)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("---- GET CERT ----");

	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t hashes[4 * TEE_SHA256_HASH_SIZE];
	uint8_t *ak_h  = hashes + 0 * TEE_SHA256_HASH_SIZE;
	uint8_t *ta_h  = hashes + 1 * TEE_SHA256_HASH_SIZE;
	uint8_t *sys_h = hashes + 2 * TEE_SHA256_HASH_SIZE;
	uint8_t *usr_h = hashes + 3 * TEE_SHA256_HASH_SIZE;
	size_t sig_len = RSA_SIG_SIZE_BYTE;
	uint8_t sig[sig_len];
	uint8_t hash_of_hash[TEE_SHA256_HASH_SIZE];
	struct user_ta_ctx *utc;
	uint8_t *dst = NULL;

	/* generating Attestation Key (AK) Hash */
	res = get_sha256(ak_h, p[0].memref.buffer, p[0].memref.size);
	if (res)
		return res;
	DMSG("Hash of the AK is calculated!");

	/* generating the Hash of the user data */
	res = get_sha256(usr_h, p[1].memref.buffer, p[1].memref.size);
	if (res)
		return res;
	DMSG("Hash of the User-Data is calculated!");

	/* get the hash of the calling TA */
	utc = to_user_ta_ctx(tee_ta_get_calling_session()->ctx);
	memcpy(ta_h, utc->ta_image_sha256, TEE_SHA256_HASH_SIZE);
	DMSG("Hash of the calling TA is saved to the return Mem!");

	/* get the system measurement from the secure boot process */
	res = attestation_get_sys_measurement(sys_h);
	if (res)
		return res;
	DMSG("System measurement is saved to the return Mem!");

	/* generate the hash over the other hashes */
	res = get_sha256(hash_of_hash,
			 hashes,
			 4 * TEE_SHA256_HASH_SIZE);
	if (res)
		return res;
	DMSG("Hashes over the other hashes is done, ready to be signed");

	/* sign this hash */
	res = acipher_sign(hash_of_hash, sizeof(hash_of_hash),
			   sig, &sig_len);
	if (res)
		return res;
	DMSG("Certificate is signed");

	/* prepare the output */
	dst = (uint8_t *)p[2].memref.buffer;

	p[2].memref.size = sizeof(sig) + sizeof(hashes);
	memcpy(dst, hashes, sizeof(hashes));
	memcpy(dst + sizeof(hashes), sig, sizeof(sig));

	DMSG("---- Certificate was issued! ----");
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct tee_ta_session *s = NULL;

	DMSG("Attestation-PTA got called (cmd): %d", cmd);
	switch (cmd) {
	case ATTESTATION_CMD_SET_DATA:
		return set_data(ptypes, params);

	case ATTESTATION_CMD_GET_CERT:
		/* Check that we're called from a user TA */
		s = tee_ta_get_calling_session();
		DMSG(" ATTESTATION_CMD_GET_CERT has been called");
		if (!s)
			return TEE_ERROR_ACCESS_DENIED;
		if (!is_user_ta_ctx(s->ctx))
			return TEE_ERROR_ACCESS_DENIED;
		return get_cert(ptypes, params);

	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = ATTESTATION_UUID, .name = "attestation.pta",
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
