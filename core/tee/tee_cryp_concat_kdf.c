/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee/tee_cryp_concat_kdf.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>
#include <stdlib.h>
#include <string.h>

TEE_Result tee_cryp_concat_kdf(uint32_t hash_id, const uint8_t *shared_secret,
			       size_t shared_secret_len,
			       const uint8_t *other_info,
			       size_t other_info_len, uint8_t *derived_key,
			       size_t derived_key_len)
{
	TEE_Result res;
	size_t ctx_size, hash_len, i, n, sz;
	void *ctx = NULL;
	uint8_t tmp[TEE_MAX_HASH_SIZE];
	uint32_t be_count;
	uint8_t *out = derived_key;
	uint32_t hash_algo = TEE_ALG_HASH_ALGO(hash_id);
	const struct hash_ops *hash = &crypto_ops.hash;

	if (!hash->get_ctx_size || !hash->init || !hash->update ||
	    !hash->final) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}

	res = hash->get_ctx_size(hash_algo, &ctx_size);
	if (res != TEE_SUCCESS)
		goto out;

	ctx = malloc(ctx_size);
	if (!ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = tee_hash_get_digest_size(hash_algo, &hash_len);
	if (res != TEE_SUCCESS)
		goto out;

	n = derived_key_len / hash_len;
	sz = hash_len;
	for (i = 1; i <= n + 1; i++) {
		be_count = TEE_U32_TO_BIG_ENDIAN(i);

		res = hash->init(ctx, hash_algo);
		if (res != TEE_SUCCESS)
			goto out;
		res = hash->update(ctx, hash_algo, (uint8_t *)&be_count,
				   sizeof(be_count));
		if (res != TEE_SUCCESS)
			goto out;
		res = hash->update(ctx, hash_algo, shared_secret,
				   shared_secret_len);
		if (res != TEE_SUCCESS)
			goto out;
		if (other_info && other_info_len) {
			res = hash->update(ctx, hash_algo, other_info,
					   other_info_len);
			if (res != TEE_SUCCESS)
				goto out;
		}
		res = hash->final(ctx, hash_algo, tmp, sizeof(tmp));
		if (res != TEE_SUCCESS)
			goto out;

		if (i == n + 1)
			sz = derived_key_len % hash_len;
		memcpy(out, tmp, sz);
		out += sz;
	}
	res = TEE_SUCCESS;
out:
	free(ctx);
	return res;
}
