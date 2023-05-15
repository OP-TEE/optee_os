// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_concat_kdf.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

TEE_Result tee_cryp_concat_kdf(uint32_t hash_id, const uint8_t *shared_secret,
			       size_t shared_secret_len,
			       const uint8_t *other_info,
			       size_t other_info_len, uint8_t *derived_key,
			       size_t derived_key_len)
{
	TEE_Result res;
	size_t hash_len, i, n, sz;
	void *ctx = NULL;
	uint8_t tmp[TEE_MAX_HASH_SIZE];
	uint32_t be_count;
	uint8_t *out = derived_key;
	uint32_t hash_algo = TEE_ALG_HASH_ALGO(hash_id);

	res = crypto_hash_alloc_ctx(&ctx, hash_algo);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_alg_get_digest_size(hash_algo, &hash_len);
	if (res != TEE_SUCCESS)
		goto out;

	n = derived_key_len / hash_len;
	sz = hash_len;
	for (i = 1; i <= n + 1; i++) {
		be_count = TEE_U32_TO_BIG_ENDIAN(i);

		res = crypto_hash_init(ctx);
		if (res != TEE_SUCCESS)
			goto out;
		res = crypto_hash_update(ctx, (uint8_t *)&be_count,
					 sizeof(be_count));
		if (res != TEE_SUCCESS)
			goto out;
		res = crypto_hash_update(ctx, shared_secret, shared_secret_len);
		if (res != TEE_SUCCESS)
			goto out;
		if (other_info && other_info_len) {
			res = crypto_hash_update(ctx, other_info,
						 other_info_len);
			if (res != TEE_SUCCESS)
				goto out;
		}
		res = crypto_hash_final(ctx, tmp, sizeof(tmp));
		if (res != TEE_SUCCESS)
			goto out;

		if (i == n + 1)
			sz = derived_key_len % hash_len;
		memcpy(out, tmp, sz);
		out += sz;
	}
	res = TEE_SUCCESS;
out:
	crypto_hash_free_ctx(ctx);
	return res;
}
