// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2022, Linaro Limited
 */

#include <crypto/crypto.h>
#include <fault_mitigation.h>
#include <kernel/panic.h>
#include <mempool.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <string.h>
#include <ta_pub_key.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <tee/uuid.h>
#include <utee_defines.h>
#include <util.h>

struct shdr *shdr_alloc_and_copy(size_t offs, const void *img, size_t img_size)
{
	size_t shdr_size;
	struct shdr *shdr;
	vaddr_t img_va = (vaddr_t)img;
	vaddr_t tmp = 0;
	size_t end = 0;

	if (ADD_OVERFLOW(offs, sizeof(struct shdr), &end) || end > img_size)
		return NULL;

	shdr_size = SHDR_GET_SIZE((const struct shdr *)(img_va + offs));
	if (!shdr_size || ADD_OVERFLOW(offs, shdr_size, &end) || end > img_size)
		return NULL;

	if (ADD_OVERFLOW(img_va, shdr_size, &tmp))
		return NULL;

	shdr = malloc(shdr_size);
	if (!shdr)
		return NULL;
	memcpy(shdr, (const uint8_t *)img + offs, shdr_size);

	/* Check that the data wasn't modified before the copy was completed */
	if (shdr_size != SHDR_GET_SIZE(shdr)) {
		free(shdr);
		return NULL;
	}

	return shdr;
}

static bool is_weak_hash_algo(uint32_t algo)
{
	return algo == TEE_ALG_MD5 || algo == TEE_ALG_SHA1 ||
	       algo == TEE_ALG_MD5SHA1;
}

TEE_Result shdr_verify_signature(const struct shdr *shdr)
{
	struct rsa_public_key key = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	struct ftmn ftmn = { };
	unsigned int err_incr = 2;
	size_t hash_size = 0;
	size_t hash_algo = 0;

	if (shdr->magic != SHDR_MAGIC)
		goto err;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != TEE_MAIN_ALGO_RSA)
		goto err;

	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	if (is_weak_hash_algo(hash_algo))
		goto err;

	res = tee_alg_get_digest_size(hash_algo, &hash_size);
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

	FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
		       crypto_acipher_rsassa_verify, shdr->algo, &key,
		       shdr->hash_size, SHDR_GET_HASH(shdr), shdr->hash_size,
		       SHDR_GET_SIG(shdr), shdr->sig_size);
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

static const struct shdr_subkey_attr *
find_attr(const struct shdr_subkey *subkey, uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < subkey->attr_count; n++)
		if (subkey->attrs[n].id == id)
			return subkey->attrs + n;

	return NULL;
}

static TEE_Result load_rsa_key(const struct shdr_subkey *subkey,
			       struct rsa_public_key **key_pp)
{
	const uint8_t *base = (const uint8_t *)subkey;
	const struct shdr_subkey_attr *pub_exp = NULL;
	const struct shdr_subkey_attr *modulus = NULL;
	struct rsa_public_key *key = NULL;
	TEE_Result res = TEE_SUCCESS;

	pub_exp = find_attr(subkey, TEE_ATTR_RSA_PUBLIC_EXPONENT);
	if (!pub_exp)
		return TEE_ERROR_SECURITY;
	modulus = find_attr(subkey, TEE_ATTR_RSA_MODULUS);
	if (!modulus)
		return TEE_ERROR_SECURITY;

	key = calloc(1, sizeof(*key));
	if (!key)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = crypto_acipher_alloc_rsa_public_key(key, modulus->size * 8);
	if (res)
		goto err_key;

	res = crypto_bignum_bin2bn(base + pub_exp->offs, pub_exp->size, key->e);
	if (res)
		goto err;
	res = crypto_bignum_bin2bn(base + modulus->offs, modulus->size, key->n);
	if (res)
		goto err;

	*key_pp = key;
	return TEE_SUCCESS;
err:
	crypto_acipher_free_rsa_public_key(key);
err_key:
	free(key);
	return TEE_ERROR_SECURITY;
}

static TEE_Result check_attrs(const struct shdr_subkey *subkey, size_t img_size)
{
	const struct shdr_subkey_attr *attrs = subkey->attrs;
	size_t end = 0;
	size_t n = 0;

	if (MUL_OVERFLOW(subkey->attr_count, sizeof(*attrs), &end) ||
	    ADD_OVERFLOW(end, sizeof(*subkey), &end) ||
	    end > img_size)
		return TEE_ERROR_SECURITY;

	for (n = 0; n < subkey->attr_count; n++)
		if (ADD_OVERFLOW(attrs[n].offs, attrs[n].size, &end) ||
		    end > img_size)
			return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

static TEE_Result calc_next_uuid(uint8_t uuid[sizeof(TEE_UUID)],
				 const uint8_t my_uuid[sizeof(TEE_UUID)],
				 const void *ns_name, size_t name_size)
{
	TEE_Result res = TEE_ERROR_SECURITY;
	void *ctx = NULL;
	struct {
		uint8_t digest[TEE_SHA1_HASH_SIZE];
		TEE_UUID uuid;
		char name_str[];
	} *tmp = NULL;

	if (!name_size) {
		memcpy(uuid, my_uuid, sizeof(TEE_UUID));
		return TEE_SUCCESS;
	}

	/*
	 * RFC 4122 requires a SHA-1 digest for UUID v5. Use SHA-512
	 * instead for better collision resistance.
	 */
	if (crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA512))
		return TEE_ERROR_SECURITY;

	tmp = mempool_alloc(mempool_default, sizeof(*tmp) + name_size);
	if (!tmp)
		goto out_ctx;
	memcpy(tmp->name_str, ns_name, name_size);

	if (crypto_hash_init(ctx) ||
	    crypto_hash_update(ctx, my_uuid, sizeof(TEE_UUID)) ||
	    crypto_hash_update(ctx, (const void *)tmp->name_str,
			       strnlen(tmp->name_str, name_size)) ||
	    crypto_hash_final(ctx, tmp->digest, sizeof(tmp->digest)))
		goto out_mempool;

	tee_uuid_from_octets(&tmp->uuid, tmp->digest);
	/*
	 * Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to 5.
	 */
	tmp->uuid.timeHiAndVersion &= ~SHIFT_U32(0xf, 12);
	tmp->uuid.timeHiAndVersion |= SHIFT_U32(5, 12);
	/*
	 * Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
	tmp->uuid.clockSeqAndNode[0] &= ~BIT(6);
	tmp->uuid.clockSeqAndNode[0] |= BIT(7);

	tee_uuid_to_octets(uuid, &tmp->uuid);
	res = TEE_SUCCESS;

out_mempool:
	mempool_free(mempool_default, tmp);
out_ctx:
	crypto_hash_free_ctx(ctx);

	return res;
}

TEE_Result shdr_load_pub_key(const struct shdr *shdr, size_t offs,
			     const uint8_t *ns_img, size_t ns_img_size,
			     const uint8_t next_uuid[sizeof(TEE_UUID)],
			     uint32_t max_depth, struct shdr_pub_key *key)
{
	struct shdr_subkey *subkey = NULL;
	TEE_Result res = TEE_SUCCESS;
	void *digest = NULL;
	uint8_t *img = NULL;
	void *ctx = NULL;
	size_t end = 0;

	if (shdr->img_type != SHDR_SUBKEY)
		return TEE_ERROR_SECURITY;

	if (shdr->img_size < sizeof(*subkey))
		return TEE_ERROR_SECURITY;

	if (ADD_OVERFLOW(shdr->img_size, offs, &end) || end > ns_img_size)
		return TEE_ERROR_SECURITY;

	img = mempool_alloc(mempool_default, shdr->img_size + shdr->hash_size);
	if (!img)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(img + shdr->hash_size, ns_img + offs, shdr->img_size);
	subkey = (void *)(img + shdr->hash_size);
	digest = img;

	if (crypto_hash_alloc_ctx(&ctx, TEE_DIGEST_HASH_TO_ALGO(shdr->algo))) {
		res = TEE_ERROR_SECURITY;
		goto out_mempool;
	}

	if (crypto_hash_init(ctx) ||
	    crypto_hash_update(ctx, (const void *)shdr, sizeof(*shdr)) ||
	    crypto_hash_update(ctx, (const void *)subkey, shdr->img_size) ||
	    crypto_hash_final(ctx, digest, shdr->hash_size) ||
	    memcmp(digest, SHDR_GET_HASH(shdr), shdr->hash_size)) {
		res = TEE_ERROR_SECURITY;
		goto out_ctx;
	}

	res = check_attrs(subkey, shdr->img_size);
	if (res)
		goto out_ctx;

	if (subkey->max_depth >= max_depth) {
		res = TEE_ERROR_SECURITY;
		goto out_ctx;
	}
	if (next_uuid && memcmp(next_uuid, subkey->uuid, sizeof(TEE_UUID))) {
		res = TEE_ERROR_SECURITY;
		goto out_ctx;
	}

	key->max_depth = subkey->max_depth;
	key->name_size = subkey->name_size;
	memcpy(key->uuid, subkey->uuid, sizeof(TEE_UUID));
	if (ADD_OVERFLOW(key->name_size, offs + shdr->img_size, &end) ||
	    end > ns_img_size) {
		res = TEE_ERROR_SECURITY;
		goto out_ctx;
	}
	res = calc_next_uuid(key->next_uuid, key->uuid,
			     ns_img + offs + shdr->img_size, key->name_size);
	if (res)
		goto out_ctx;

	key->main_algo = TEE_ALG_GET_MAIN_ALG(subkey->algo);
	switch (key->main_algo) {
	case TEE_MAIN_ALGO_RSA:
		res = load_rsa_key(subkey, &key->pub_key.rsa);
		break;
	default:
		res = TEE_ERROR_SECURITY;
		break;
	}

out_ctx:
	crypto_hash_free_ctx(ctx);
out_mempool:
	mempool_free(mempool_default, img);
	return res;
}

void shdr_free_pub_key(struct shdr_pub_key *key)
{
	if (key) {
		switch (key->main_algo) {
		case TEE_MAIN_ALGO_RSA:
			crypto_acipher_free_rsa_public_key(key->pub_key.rsa);
			free(key->pub_key.rsa);
			break;
		default:
			panic();
		}
	}
}

TEE_Result shdr_verify_signature2(struct shdr_pub_key *key,
				  const struct shdr *shdr)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int err_incr = 2;
	struct ftmn ftmn = { };
	size_t hash_size = 0;
	size_t hash_algo = 0;

	if (shdr->magic != SHDR_MAGIC)
		goto err;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != key->main_algo)
		goto err;

	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	if (is_weak_hash_algo(hash_algo))
		goto err;

	if (tee_alg_get_digest_size(hash_algo, &hash_size) ||
	    hash_size != shdr->hash_size)
		goto err;

	switch (key->main_algo) {
	case TEE_MAIN_ALGO_RSA:
		FTMN_CALL_FUNC(res, &ftmn, FTMN_INCR0,
			       crypto_acipher_rsassa_verify, shdr->algo,
			       key->pub_key.rsa, shdr->hash_size,
			       SHDR_GET_HASH(shdr), shdr->hash_size,
			       SHDR_GET_SIG(shdr), shdr->sig_size);
		break;
	default:
		panic();
	}

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
	return res;
}
