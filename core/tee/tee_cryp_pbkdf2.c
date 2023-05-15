// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_pbkdf2.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

struct hmac_parms {
	uint32_t algo;
	size_t hash_len;
	void *ctx;
};

struct pbkdf2_parms {
	const uint8_t *password;
	size_t password_len;
	const uint8_t *salt;
	size_t salt_len;
	uint32_t iteration_count;
};

static TEE_Result pbkdf2_f(uint8_t *out, size_t len, uint32_t idx,
			   struct hmac_parms *h, struct pbkdf2_parms *p)
{
	TEE_Result res;
	uint8_t u[TEE_MAX_HASH_SIZE];
	uint32_t be_index;
	size_t i, j;

	memset(out, 0, len);
	for (i = 1; i <= p->iteration_count; i++) {
		res = crypto_mac_init(h->ctx, p->password, p->password_len);
		if (res != TEE_SUCCESS)
			return res;

		if (i == 1) {
			if (p->salt && p->salt_len) {
				res = crypto_mac_update(h->ctx, p->salt,
							p->salt_len);
				if (res != TEE_SUCCESS)
					return res;
			}

			be_index = TEE_U32_TO_BIG_ENDIAN(idx);

			res = crypto_mac_update(h->ctx, (uint8_t *)&be_index,
						sizeof(be_index));
			if (res != TEE_SUCCESS)
				return res;
		} else {
			res = crypto_mac_update(h->ctx, u, h->hash_len);
			if (res != TEE_SUCCESS)
				return res;
		}

		res = crypto_mac_final(h->ctx, u, sizeof(u));
		if (res != TEE_SUCCESS)
			return res;

		for (j = 0; j < len; j++)
			out[j] ^= u[j];
	}
	return TEE_SUCCESS;
}

TEE_Result tee_cryp_pbkdf2(uint32_t hash_id, const uint8_t *password,
			   size_t password_len, const uint8_t *salt,
			   size_t salt_len, uint32_t iteration_count,
			   uint8_t *derived_key, size_t derived_key_len)
{
	TEE_Result res;
	size_t i, l, r;
	uint8_t *out = derived_key;
	struct pbkdf2_parms pbkdf2_parms;
	struct hmac_parms hmac_parms = {0, };

	hmac_parms.algo = TEE_ALG_HMAC_ALGO(hash_id);

	res = tee_alg_get_digest_size(hmac_parms.algo, &hmac_parms.hash_len);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_mac_alloc_ctx(&hmac_parms.ctx, hmac_parms.algo);
	if (res != TEE_SUCCESS)
		return res;

	pbkdf2_parms.password = password;
	pbkdf2_parms.password_len = password_len;
	pbkdf2_parms.salt = salt;
	pbkdf2_parms.salt_len = salt_len;
	pbkdf2_parms.iteration_count = iteration_count;

	l = derived_key_len / hmac_parms.hash_len;
	r = derived_key_len % hmac_parms.hash_len;

	for (i = 1; i <= l; i++) {
		res = pbkdf2_f(out, hmac_parms.hash_len, i, &hmac_parms,
			       &pbkdf2_parms);
		if (res != TEE_SUCCESS)
			goto out;
		out += hmac_parms.hash_len;
	}
	if (r)
		res = pbkdf2_f(out, r, i, &hmac_parms, &pbkdf2_parms);

out:
	crypto_mac_free_ctx(hmac_parms.ctx);
	return res;
}
