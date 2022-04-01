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
#include <fault_mitigation.h>

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
	struct rsa_public_key key = { };
	TEE_Result res;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	struct ftmn ftmn = { };
	unsigned int err_incr = 2;
	size_t hash_size;

	if (shdr->magic != SHDR_MAGIC)
		goto err;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != TEE_MAIN_ALGO_RSA)
		goto err;

	res = tee_alg_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(shdr->algo),
				      &hash_size);
	if (res)
		goto err;
	if (hash_size != shdr->hash_size)
		goto err;

	res = crypto_acipher_alloc_rsa_public_key(&key,
						  ta_pub_key_modulus_size * 8);
	if (res)
		goto err;

	res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res)
		goto err;
	res = crypto_bignum_bin2bn(ta_pub_key_modulus, ta_pub_key_modulus_size,
				   key.n);
	if (res)
		goto err;

	FTMN_PUSH_LINKED_CALL(&ftmn,
			      FTMN_FUNC_HASH("crypto_acipher_rsassa_verify"));
	res = crypto_acipher_rsassa_verify(shdr->algo, &key, shdr->hash_size,
					   SHDR_GET_HASH(shdr), shdr->hash_size,
					   SHDR_GET_SIG(shdr), shdr->sig_size);
	FTMN_SET_CHECK_RES_FROM_CALL(&ftmn, FTMN_INCR0, res);
	FTMN_POP_LINKED_CALL(&ftmn);
	if (!res) {
		ftmn_checkpoint(&ftmn, FTMN_INCR0);
		goto out;
	}
	err_incr = 1;
err:
	res = TEE_ERROR_SECURITY;
	FTMN_SET_CHECK_RES_NOT_ZERO(&ftmn, err_incr * FTMN_INCR0, res);
out:
	FTMN_CALLEE_DONE_CHECK(&ftmn, FTMN_INCR0, FTMN_STEP_COUNT(2), res);
	crypto_acipher_free_rsa_public_key(&key);
	return res;
}
