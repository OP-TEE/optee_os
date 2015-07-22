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

#include <tee/tee_cryp_hkdf.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <stdlib.h>
#include <string.h>
#include <utee_defines.h>


static const uint8_t zero_salt[TEE_MAX_HASH_SIZE];

static TEE_Result hkdf_extract(uint32_t hash_id, const uint8_t *ikm,
			       size_t ikm_len, const uint8_t *salt,
			       size_t salt_len, uint8_t *prk, size_t *prk_len)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx = NULL;
	uint32_t hash_algo = TEE_ALG_HASH_ALGO(hash_id);
	uint32_t hmac_algo = (TEE_OPERATION_MAC << 28) | hash_id;
	const struct mac_ops *m = &crypto_ops.mac;

	if (!m->get_ctx_size || !m->init || !m->update) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}

	if (!salt || !salt_len) {
		/*
		 * RFC 5869 section 2.2:
		 * If not provided, [the salt] is set to a string of HashLen
		 * zeros
		 */
		salt = zero_salt;
		res = tee_hash_get_digest_size(hash_algo, &salt_len);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = m->get_ctx_size(hmac_algo, &ctx_size);
	if (res != TEE_SUCCESS)
		goto out;

	ctx = malloc(ctx_size);
	if (!ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * RFC 5869 section 2.1: "Note that in the extract step, 'IKM' is used
	 * as the HMAC input, not as the HMAC key."
	 * Therefore, salt is the HMAC key in the formula from section 2.2:
	 * "PRK = HMAC-Hash(salt, IKM)"
	 */
	res = m->init(ctx, hmac_algo, salt, salt_len);
	if (res != TEE_SUCCESS)
		goto out;

	res = m->update(ctx, hmac_algo, ikm, ikm_len);
	if (res != TEE_SUCCESS)
		goto out;

	res = m->final(ctx, hmac_algo, prk, *prk_len);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_hash_get_digest_size(hash_algo, prk_len);
out:
	free(ctx);
	return res;
}

static TEE_Result hkdf_expand(uint32_t hash_id, const uint8_t *prk,
			      size_t prk_len, const uint8_t *info,
			      size_t info_len, uint8_t *okm, size_t okm_len)
{
	uint8_t tn[TEE_MAX_HASH_SIZE];
	size_t tn_len, hash_len, i, n, where, ctx_size;
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;
	const struct mac_ops *m = &crypto_ops.mac;
	uint32_t hash_algo = TEE_ALG_HASH_ALGO(hash_id);
	uint32_t hmac_algo = TEE_ALG_HMAC_ALGO(hash_id);

	if (!m->get_ctx_size || !m->init || !m->update || !m->final) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}

	res = tee_hash_get_digest_size(hash_algo, &hash_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (!okm || prk_len < hash_len) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (!info)
		info_len = 0;

	res = m->get_ctx_size(hmac_algo, &ctx_size);
	if (res != TEE_SUCCESS)
		goto out;

	ctx = malloc(ctx_size);
	if (!ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* N = ceil(L/HashLen) */
	n = okm_len / hash_len;
	if ((okm_len % hash_len) != 0)
		n++;

	if (n > 255) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}


	/*
	 * RFC 5869 section 2.3
	 *   T = T(1) | T(2) | T(3) | ... | T(N)
	 *   OKM = first L octets of T
	 *   T(0) = empty string (zero length)
	 *   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	 *   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	 *   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
	 *   ...
	 */
	tn_len = 0;
	where = 0;
	for (i = 1; i <= n; i++) {
		uint8_t c = i;

		res = m->init(ctx, hmac_algo, prk, prk_len);
		if (res != TEE_SUCCESS)
			goto out;
		res = m->update(ctx, hmac_algo, tn, tn_len);
		if (res != TEE_SUCCESS)
			goto out;
		res = m->update(ctx, hmac_algo, info, info_len);
		if (res != TEE_SUCCESS)
			goto out;
		res = m->update(ctx, hmac_algo, &c, 1);
		if (res != TEE_SUCCESS)
			goto out;
		res = m->final(ctx, hmac_algo, tn, sizeof(tn));
		if (res != TEE_SUCCESS)
			goto out;

		memcpy(okm + where, tn, (i < n) ? hash_len : (okm_len - where));
		where += hash_len;
		tn_len = hash_len;
	}

out:
	free(ctx);
	return res;
}

TEE_Result tee_cryp_hkdf(uint32_t hash_id, const uint8_t *ikm, size_t ikm_len,
			 const uint8_t *salt, size_t salt_len,
			 const uint8_t *info, size_t info_len, uint8_t *okm,
			 size_t okm_len)
{
	TEE_Result res;
	uint8_t prk[TEE_MAX_HASH_SIZE];
	size_t prk_len = sizeof(prk);

	res = hkdf_extract(hash_id, ikm, ikm_len, salt, salt_len, prk,
			   &prk_len);
	if (res != TEE_SUCCESS)
		return res;
	res = hkdf_expand(hash_id, prk, prk_len, info, info_len, okm,
			  okm_len);

	return res;
}
