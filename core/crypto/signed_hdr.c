// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2017, Linaro Limited
 */

#include <crypto/crypto.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <string.h>
#include <ta_pub_key.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>
#include <util.h>

struct shdr *shdr_alloc_and_copy(const struct shdr *img, size_t img_size)
{
	size_t shdr_size;
	struct shdr *shdr;
	vaddr_t img_va = (vaddr_t)img;
	vaddr_t tmp = 0;

	if (img_size < sizeof(struct shdr))
		return NULL;

	shdr_size = SHDR_GET_SIZE(img);
	if (img_size < shdr_size)
		return NULL;

	if (ADD_OVERFLOW(img_va, shdr_size, &tmp))
		return NULL;

	shdr = malloc(shdr_size);
	if (!shdr)
		return NULL;
	memcpy(shdr, img, shdr_size);

	/* Check that the data wasn't modified before the copy was completed */
	if (shdr_size != SHDR_GET_SIZE(shdr)) {
		free(shdr);
		return NULL;
	}

	return shdr;
}

TEE_Result shdr_verify_signature(const struct shdr *shdr)
{
	struct rsa_public_key key;
	TEE_Result res;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	size_t hash_size;

	if (shdr->magic != SHDR_MAGIC)
		return TEE_ERROR_SECURITY;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != TEE_MAIN_ALGO_RSA)
		return TEE_ERROR_SECURITY;

	res = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(shdr->algo),
				      &hash_size);
	if (res)
		return TEE_ERROR_SECURITY;
	if (hash_size != shdr->hash_size)
		return TEE_ERROR_SECURITY;

	res = crypto_acipher_alloc_rsa_public_key(&key, shdr->sig_size);
	if (res)
		return TEE_ERROR_SECURITY;

	res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res)
		goto out;
	res = crypto_bignum_bin2bn(ta_pub_key_modulus, ta_pub_key_modulus_size,
				   key.n);
	if (res)
		goto out;

	res = crypto_acipher_rsassa_verify(shdr->algo, &key, shdr->hash_size,
					   SHDR_GET_HASH(shdr), shdr->hash_size,
					   SHDR_GET_SIG(shdr), shdr->sig_size);
out:
	crypto_acipher_free_rsa_public_key(&key);
	if (res)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}
