// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020 Huawei Technologies Co., Ltd
 */

#include <crypto/crypto.h>
#include <crypto/sm2-kdf.h>
#include <io.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <unistd.h>
#include <utee_defines.h>

/*
 * GM/T 0003.1‒2012 Part 4 Sections 5.4.2 and 5.4.3
 * GM/T 0003.1‒2012 Part 5 Sections 5.4.2 and 5.4.3
 * Key derivation function based on the SM3 hash function
 */
TEE_Result sm2_kdf(const uint8_t *Z, size_t Z_len, uint8_t *t, size_t tlen)
{
	TEE_Result res = TEE_SUCCESS;
	size_t remain = tlen;
	uint32_t count = 1;
	uint32_t be_count = 0;
	void *ctx = NULL;
	uint8_t *out = t;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SM3);
	if (res)
		return res;

	while (remain) {
		uint8_t tmp[TEE_SM3_HASH_SIZE] = { };
		uint8_t *buf = NULL;

		if (remain >= TEE_SM3_HASH_SIZE)
			buf = out;
		else
			buf = tmp;

		put_be32(&be_count, count);
		res = crypto_hash_init(ctx);
		if (res)
			goto out;
		res = crypto_hash_update(ctx, Z, Z_len);
		if (res)
			goto out;
		res = crypto_hash_update(ctx, (const uint8_t *)&be_count,
					 sizeof(be_count));
		if (res)
			goto out;
		res = crypto_hash_final(ctx, buf, TEE_SM3_HASH_SIZE);
		if (res)
			goto out;

		if (remain < TEE_SM3_HASH_SIZE) {
			memcpy(out, tmp, remain);
			break;
		}

		out += TEE_SM3_HASH_SIZE;
		remain -= TEE_SM3_HASH_SIZE;
		count++;
	}
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

