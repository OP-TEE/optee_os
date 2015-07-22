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

#include <tee/tee_cryp_pbkdf2.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>
#include <stdlib.h>
#include <string.h>

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
	const struct mac_ops *mac = &crypto_ops.mac;

	memset(out, 0, len);
	for (i = 1; i <= p->iteration_count; i++) {
		res = mac->init(h->ctx, h->algo, p->password, p->password_len);
		if (res != TEE_SUCCESS)
			return res;

		if (i == 1) {
			if (p->salt && p->salt_len) {
				res = mac->update(h->ctx, h->algo, p->salt,
						  p->salt_len);
				if (res != TEE_SUCCESS)
					return res;
			}

			be_index = TEE_U32_TO_BIG_ENDIAN(idx);

			res = mac->update(h->ctx, h->algo,
					  (uint8_t *)&be_index,
					  sizeof(be_index));
			if (res != TEE_SUCCESS)
				return res;
		} else {
			res = mac->update(h->ctx, h->algo, u, h->hash_len);
			if (res != TEE_SUCCESS)
				return res;
		}

		res = mac->final(h->ctx, h->algo, u, sizeof(u));
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
	size_t ctx_size, i, l, r;
	uint8_t *out = derived_key;
	struct pbkdf2_parms pbkdf2_parms;
	struct hmac_parms hmac_parms = {0, };
	const struct mac_ops *mac = &crypto_ops.mac;

	if (!mac->get_ctx_size || !mac->init || !mac->update ||
	    !mac->final)
		return TEE_ERROR_NOT_IMPLEMENTED;

	hmac_parms.algo = TEE_ALG_HMAC_ALGO(hash_id);

	res = tee_mac_get_digest_size(hmac_parms.algo, &hmac_parms.hash_len);
	if (res != TEE_SUCCESS)
		return res;

	res = mac->get_ctx_size(hmac_parms.algo, &ctx_size);
	if (res != TEE_SUCCESS)
		return res;

	hmac_parms.ctx = malloc(ctx_size);
	if (!hmac_parms.ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

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
	free(hmac_parms.ctx);
	return res;
}
