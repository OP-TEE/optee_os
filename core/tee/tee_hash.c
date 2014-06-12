/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <tomcrypt.h>
#include <tee/tee_hash.h>
#include <kernel/tee_core_trace.h>
#include "tee_ltc_wrapper.h"

#define MAX_DIGEST 64

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size)
{
	int ltc_res, ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = hash_descriptor[ltc_hashindex].hashsize;
	return TEE_SUCCESS;
}

TEE_Result tee_hash_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*size = sizeof(hash_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_hash_init(void *ctx, uint32_t algo)
{
	int ltc_res, ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex].init(ctx) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result tee_hash_update(void *ctx, uint32_t algo,
			   const uint8_t *data, size_t len)
{
	int ltc_res, ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex].process(ctx, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result tee_hash_final(void *ctx, uint32_t algo, uint8_t *digest, size_t len)
{
	int ltc_res, ltc_hashindex;
	size_t hash_size;
	uint8_t block_digest[MAX_DIGEST], *tmp_digest;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_size = hash_descriptor[ltc_hashindex].hashsize;
	if ((hash_size < len) || (hash_size > MAX_DIGEST)) {
		/*
		 * Caller is asking for more bytes than the computation
		 * will produce ... might be something wrong
		 */
		return  TEE_ERROR_BAD_PARAMETERS;
	}

	if (hash_size > len) {
		/* use a tempory buffer */
		tmp_digest = block_digest;
	} else {
		tmp_digest = digest;
	}

	if (hash_descriptor[ltc_hashindex].done(ctx, tmp_digest) == CRYPT_OK) {
		if (hash_size > len)
			memcpy(digest, tmp_digest, len);
	} else {
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_hash_createdigest(
		uint32_t algo,
		const uint8_t *data, size_t datalen,
		uint8_t *digest, size_t digestlen)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	void *ctx = NULL;
	size_t ctxsize;

	if (tee_hash_get_ctx_size(algo, &ctxsize) != TEE_SUCCESS) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ctx = malloc(ctxsize);
	if (ctx == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (tee_hash_init(ctx, algo) != TEE_SUCCESS)
		goto out;

	if (datalen != 0) {
		if (tee_hash_update(ctx, algo, data, datalen) != TEE_SUCCESS)
			goto out;
	}

	if (tee_hash_final(ctx, algo, digest, digestlen) != TEE_SUCCESS)
		goto out;

	res = TEE_SUCCESS;

out:
	if (ctx)
		free(ctx);

	return res;
}

TEE_Result tee_hash_check(
		uint32_t algo,
		const uint8_t *hash, size_t hash_size,
		const uint8_t *data, size_t data_size)
{
	TEE_Result res;
	uint8_t digest[MAX_DIGEST];
	size_t digestlen;

	res = tee_hash_get_digest_size(algo, &digestlen);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((hash_size == 0) ||
	    (digestlen < hash_size) ||
	    (digestlen > MAX_DIGEST))
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_createdigest(algo, data, data_size, digest, digestlen);
	if (res != TEE_SUCCESS)
		return res;

	if (memcmp(digest, hash, hash_size) != 0)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
