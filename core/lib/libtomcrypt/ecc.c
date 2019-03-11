// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <tomcrypt.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
					    size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
					       size_t key_size_bits __unused)
{
	memset(s, 0, sizeof(*s));
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
}

/*
 * curve is part of TEE_ECC_CURVE_NIST_P192,...
 * algo is part of TEE_ALG_ECDSA_P192,..., and 0 if we do not have it
 */
static TEE_Result ecc_get_keysize(uint32_t curve, uint32_t algo,
				  size_t *key_size_bytes, size_t *key_size_bits)
{
	/*
	 * Excerpt of libtomcrypt documentation:
	 * ecc_make_key(... key_size ...): The keysize is the size of the
	 * modulus in bytes desired. Currently directly supported values
	 * are 12, 16, 20, 24, 28, 32, 48, and 65 bytes which correspond
	 * to key sizes of 112, 128, 160, 192, 224, 256, 384, and 521 bits
	 * respectively.
	 */

	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*key_size_bits = 192;
		*key_size_bytes = 24;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P192) &&
		    (algo != TEE_ALG_ECDH_P192))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		*key_size_bytes = 28;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P224) &&
		    (algo != TEE_ALG_ECDH_P224))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		*key_size_bytes = 32;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P256) &&
		    (algo != TEE_ALG_ECDH_P256))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		*key_size_bytes = 48;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P384) &&
		    (algo != TEE_ALG_ECDH_P384))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		/*
		 * set 66 instead of 65 wrt to Libtomcrypt documentation as
		 * if it the real key size
		 */
		*key_size_bytes = 66;
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P521) &&
		    (algo != TEE_ALG_ECDH_P521))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		*key_size_bits = 0;
		*key_size_bytes = 0;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	TEE_Result res;
	ecc_key ltc_tmp_key;
	int ltc_res;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;

	res = ecc_get_keysize(key->curve, 0, &key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	/* Generate the ECC key */
	ltc_res = ecc_make_key(NULL, find_prng("prng_mpa"),
			       key_size_bytes, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	/* check the size of the keys */
	if (((size_t)mp_count_bits(ltc_tmp_key.pubkey.x) > key_size_bits) ||
	    ((size_t)mp_count_bits(ltc_tmp_key.pubkey.y) > key_size_bits) ||
	    ((size_t)mp_count_bits(ltc_tmp_key.k) > key_size_bits)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* check LTC is returning z==1 */
	if (mp_count_bits(ltc_tmp_key.pubkey.z) != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Copy the key */
	ltc_mp.copy(ltc_tmp_key.k, key->d);
	ltc_mp.copy(ltc_tmp_key.pubkey.x, key->x);
	ltc_mp.copy(ltc_tmp_key.pubkey.y, key->y);

	res = TEE_SUCCESS;

exit:
	ecc_free(&ltc_tmp_key);		/* Free the temporary key */
	return res;
}

static TEE_Result ecc_compute_key_idx(ecc_key *ltc_key, size_t keysize)
{
	size_t x;

	for (x = 0; ((int)keysize > ltc_ecc_sets[x].size) &&
		    (ltc_ecc_sets[x].size != 0);
	     x++)
		;
	keysize = (size_t)ltc_ecc_sets[x].size;

	if ((keysize > ECC_MAXSIZE) || (ltc_ecc_sets[x].size == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_key->idx = -1;
	ltc_key->dp  = &ltc_ecc_sets[x];

	return TEE_SUCCESS;
}

/*
 * Given a keypair "key", populate the Libtomcrypt private key "ltc_key"
 * It also returns the key size, in bytes
 */
static TEE_Result ecc_populate_ltc_private_key(ecc_key *ltc_key,
					       struct ecc_keypair *key,
					       uint32_t algo,
					       size_t *key_size_bytes)
{
	TEE_Result res;
	size_t key_size_bits;

	memset(ltc_key, 0, sizeof(*ltc_key));
	ltc_key->type = PK_PRIVATE;
	ltc_key->k = key->d;

	/* compute the index of the ecc curve */
	res = ecc_get_keysize(key->curve, algo,
			      key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	return ecc_compute_key_idx(ltc_key, *key_size_bytes);
}

/*
 * Given a public "key", populate the Libtomcrypt public key "ltc_key"
 * It also returns the key size, in bytes
 */
static TEE_Result ecc_populate_ltc_public_key(ecc_key *ltc_key,
					      struct ecc_public_key *key,
					      void *key_z,
					      uint32_t algo,
					      size_t *key_size_bytes)
{
	TEE_Result res;
	size_t key_size_bits;
	uint8_t one[1] = { 1 };


	memset(ltc_key, 0, sizeof(*ltc_key));
	ltc_key->type = PK_PUBLIC;
	ltc_key->pubkey.x = key->x;
	ltc_key->pubkey.y = key->y;
	ltc_key->pubkey.z = key_z;
	mp_read_unsigned_bin(ltc_key->pubkey.z, one, sizeof(one));

	/* compute the index of the ecc curve */
	res = ecc_get_keysize(key->curve, algo,
			      key_size_bytes, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	return ecc_compute_key_idx(ltc_key, *key_size_bytes);
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	int ltc_res;
	void *r, *s;
	size_t key_size_bytes;
	ecc_key ltc_key;

	if (algo == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	res = ecc_populate_ltc_private_key(&ltc_key, key, algo,
					   &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto err;

	if (*sig_len < 2 * key_size_bytes) {
		*sig_len = 2 * key_size_bytes;
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ltc_res = ecc_sign_hash_raw(msg, msg_len, r, s,
				    NULL, find_prng("prng_mpa"), &ltc_key);

	if (ltc_res == CRYPT_OK) {
		*sig_len = 2 * key_size_bytes;
		memset(sig, 0, *sig_len);
		mp_to_unsigned_bin(r, (uint8_t *)sig + *sig_len/2 -
				   mp_unsigned_bin_size(r));
		mp_to_unsigned_bin(s, (uint8_t *)sig + *sig_len -
				   mp_unsigned_bin_size(s));
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_GENERIC;
	}

	mp_clear_multi(r, s, NULL);

err:
	return res;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	int ltc_stat;
	int ltc_res;
	void *r;
	void *s;
	void *key_z;
	size_t key_size_bytes;
	ecc_key ltc_key;

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_res = mp_init_multi(&key_z, &r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = ecc_populate_ltc_public_key(&ltc_key, key, key_z, algo,
					  &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;

	/* check keysize vs sig_len */
	if ((key_size_bytes * 2) != sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);

	ltc_res = ecc_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, &ltc_key);
	res = convert_ltc_verify_status(ltc_res, ltc_stat);
out:
	mp_clear_multi(key_z, r, s, NULL);
	return res;
}

TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	TEE_Result res;
	int ltc_res;
	ecc_key ltc_private_key;
	ecc_key ltc_public_key;
	size_t key_size_bytes;
	void *key_z;

	/* Check the curves are the same */
	if (private_key->curve != public_key->curve)
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_res = mp_init_multi(&key_z, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = ecc_populate_ltc_private_key(&ltc_private_key, private_key,
					   0, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;
	res = ecc_populate_ltc_public_key(&ltc_public_key, public_key, key_z,
					  0, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;

	ltc_res = ecc_shared_secret(&ltc_private_key, &ltc_public_key,
				    secret, secret_len);
	if (ltc_res == CRYPT_OK)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_BAD_PARAMETERS;

out:
	mp_clear_multi(key_z, NULL);
	return res;
}
