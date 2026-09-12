// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * SP800-90A Hash_DRBG instantiated with SHA-512. Entropy source: SoC
 * QRNG, via hw_get_random_bytes().
 */

#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <rng_support.h>
#include <string.h>
#include <utee_defines.h>
#include <util.h>

#include "hash_drbg.h"

#define SEED_LEN	HASH_DRBG_SEED_LEN
#define HASH_LEN	HASH_DRBG_HASH_LEN

#define RESEED_INTERVAL		((uint64_t)1 << 32)

static struct hash_drbg_state g_state;
static struct mutex g_lock = MUTEX_INITIALIZER;

struct hash_part {
	const uint8_t *buf;
	size_t len;
};

static TEE_Result sha512_parts(const struct hash_part *parts, size_t nparts,
			       uint8_t *out)
{
	void *ctx = NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA512);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	for (i = 0; i < nparts; i++) {
		res = crypto_hash_update(ctx, parts[i].buf, parts[i].len);
		if (res)
			goto out;
	}

	res = crypto_hash_final(ctx, out, HASH_LEN);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static void bn_add_be(uint8_t *v, const uint8_t *addend, size_t alen)
{
	unsigned int carry = 0;
	int i = 0;
	int j = 0;

	for (i = SEED_LEN - 1, j = (int)alen - 1; i >= 0; i--, j--) {
		carry += v[i] + (uint8_t)(j >= 0 ? addend[j] : 0);
		v[i] = (uint8_t)carry;
		carry >>= 8;
	}
}

static TEE_Result hash_df(const uint8_t *seed_material, size_t sm_len,
			  uint8_t *out, size_t out_bytes)
{
	uint32_t bits_be = TEE_U32_TO_BIG_ENDIAN((uint32_t)(out_bytes * 8));
	uint8_t counter = 1;
	uint8_t hash_out[HASH_LEN];
	size_t remaining = out_bytes;
	uint8_t *pos = out;
	TEE_Result res = TEE_SUCCESS;

	while (remaining) {
		struct hash_part parts[] = {
			{ &counter, 1 },
			{ (const uint8_t *)&bits_be, sizeof(bits_be) },
			{ seed_material, sm_len },
		};
		size_t copy = MIN(remaining, (size_t)HASH_LEN);

		res = sha512_parts(parts, ARRAY_SIZE(parts), hash_out);
		if (res)
			goto out;

		memcpy(pos, hash_out, copy);
		pos += copy;
		remaining -= copy;
		counter++;
	}

out:
	memset(hash_out, 0, sizeof(hash_out));
	return res;
}

static TEE_Result hashgen(const uint8_t *V, uint8_t *out,
			  size_t requested_bytes)
{
	uint8_t data[SEED_LEN];
	uint8_t W[HASH_LEN];
	size_t remaining = requested_bytes;
	uint8_t *pos = out;
	TEE_Result res = TEE_SUCCESS;
	const uint8_t one = 1;

	memcpy(data, V, SEED_LEN);

	while (remaining) {
		struct hash_part part = { data, SEED_LEN };
		size_t copy = MIN(remaining, (size_t)HASH_LEN);

		res = sha512_parts(&part, 1, W);
		if (res)
			goto out;

		memcpy(pos, W, copy);
		pos += copy;
		remaining -= copy;

		bn_add_be(data, &one, 1);
	}

out:
	memset(data, 0, sizeof(data));
	memset(W, 0, sizeof(W));
	return res;
}

static TEE_Result drbg_instantiate(const uint8_t *entropy, size_t elen,
				   const uint8_t *nonce, size_t nlen)
{
	uint8_t seed_material[256];
	size_t sm_len = 0;
	TEE_Result res = TEE_SUCCESS;

	if (elen + nlen > sizeof(seed_material))
		return TEE_ERROR_BAD_PARAMETERS;

	sm_len = elen + nlen;
	memcpy(seed_material, entropy, elen);
	memcpy(seed_material + elen, nonce, nlen);

	res = hash_df(seed_material, sm_len, g_state.V, SEED_LEN);
	if (res)
		goto out;

	{
		uint8_t buf[1 + SEED_LEN];

		buf[0] = 0x00;
		memcpy(buf + 1, g_state.V, SEED_LEN);
		res = hash_df(buf, sizeof(buf), g_state.C, SEED_LEN);
		memset(buf, 0, sizeof(buf));
	}
	if (res)
		goto out;

	g_state.reseed_counter = 1;
	g_state.instantiated = true;

out:
	memset(seed_material, 0, sizeof(seed_material));
	return res;
}

static TEE_Result drbg_reseed(const uint8_t *entropy, size_t elen,
			      const uint8_t *add, size_t alen)
{
	uint8_t seed_material[1 + SEED_LEN + 256];
	size_t offset = 0;
	TEE_Result res = TEE_SUCCESS;

	if (1 + SEED_LEN + elen + alen > sizeof(seed_material))
		return TEE_ERROR_BAD_PARAMETERS;

	seed_material[offset++] = 0x01;
	memcpy(seed_material + offset, g_state.V, SEED_LEN);
	offset += SEED_LEN;
	memcpy(seed_material + offset, entropy, elen);
	offset += elen;
	if (alen)
		memcpy(seed_material + offset, add, alen);
	offset += alen;

	res = hash_df(seed_material, offset, g_state.V, SEED_LEN);
	if (res)
		goto out;

	{
		uint8_t buf[1 + SEED_LEN];

		buf[0] = 0x00;
		memcpy(buf + 1, g_state.V, SEED_LEN);
		res = hash_df(buf, sizeof(buf), g_state.C, SEED_LEN);
		memset(buf, 0, sizeof(buf));
	}
	if (res)
		goto out;

	g_state.reseed_counter = 1;

out:
	memset(seed_material, 0, sizeof(seed_material));
	return res;
}

static TEE_Result drbg_generate(const uint8_t *add, size_t alen,
				uint8_t *out, size_t olen)
{
	uint8_t H[HASH_LEN];
	uint8_t rc_be[sizeof(uint64_t)];
	uint64_t rc = 0;
	TEE_Result res = TEE_SUCCESS;

	if (g_state.reseed_counter > RESEED_INTERVAL)
		return TEE_ERROR_BAD_STATE;

	if (add && alen > 0) {
		uint8_t prefix = 0x02;
		struct hash_part parts[] = {
			{ &prefix, 1 },
			{ g_state.V, SEED_LEN },
			{ add, alen },
		};

		res = sha512_parts(parts, ARRAY_SIZE(parts), H);
		if (res)
			return res;

		bn_add_be(g_state.V, H, HASH_LEN);
	}

	res = hashgen(g_state.V, out, olen);
	if (res)
		return res;

	{
		uint8_t prefix = 0x03;
		struct hash_part parts[] = {
			{ &prefix, 1 },
			{ g_state.V, SEED_LEN },
		};

		res = sha512_parts(parts, ARRAY_SIZE(parts), H);
	}
	if (res)
		return res;

	bn_add_be(g_state.V, H, HASH_LEN);
	bn_add_be(g_state.V, g_state.C, SEED_LEN);
	rc = TEE_U64_TO_BIG_ENDIAN(g_state.reseed_counter);
	memcpy(rc_be, &rc, sizeof(rc_be));
	bn_add_be(g_state.V, rc_be, sizeof(rc_be));

	g_state.reseed_counter++;
	memset(H, 0, sizeof(H));
	return TEE_SUCCESS;
}

TEE_Result hash_drbg_get_random(void *buf, size_t len)
{
	TEE_Result res = TEE_SUCCESS;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (len > HASH_DRBG_MAX_GENERATE)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&g_lock);

	if (!g_state.instantiated) {
		uint8_t entropy[SEED_LEN];
		uint8_t nonce[16];

		res = hw_get_random_bytes(entropy, sizeof(entropy));
		if (res)
			goto out;
		res = hw_get_random_bytes(nonce, sizeof(nonce));
		if (res)
			goto out;

		res = drbg_instantiate(entropy, sizeof(entropy),
				       nonce, sizeof(nonce));
		memset(entropy, 0, sizeof(entropy));
		memset(nonce, 0, sizeof(nonce));
		if (res)
			goto out;
	}

	if (g_state.reseed_counter > RESEED_INTERVAL) {
		uint8_t entropy[SEED_LEN];

		res = hw_get_random_bytes(entropy, sizeof(entropy));
		if (res)
			goto out;

		res = drbg_reseed(entropy, sizeof(entropy), NULL, 0);
		memset(entropy, 0, sizeof(entropy));
		if (res)
			goto out;
	}

	res = drbg_generate(NULL, 0, buf, len);

out:
	mutex_unlock(&g_lock);
	return res;
}

void hash_drbg_uninstantiate(void)
{
	mutex_lock(&g_lock);
	memset(&g_state, 0, sizeof(g_state));
	mutex_unlock(&g_lock);
}

#ifdef CFG_QCOM_HASH_DRBG_KAT

TEE_Result hash_drbg_test_enable(void)
{
	mutex_lock(&g_lock);
	memset(&g_state, 0, sizeof(g_state));
	g_state.test_mode = true;
	mutex_unlock(&g_lock);
	return TEE_SUCCESS;
}

TEE_Result hash_drbg_test_instantiate(const uint8_t *entropy, size_t elen,
				      const uint8_t *nonce, size_t nlen)
{
	TEE_Result res = TEE_SUCCESS;

	if (!entropy || !nonce)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&g_lock);
	if (!g_state.test_mode) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	res = drbg_instantiate(entropy, elen, nonce, nlen);
out:
	mutex_unlock(&g_lock);
	return res;
}

TEE_Result hash_drbg_test_generate(const uint8_t *add, size_t alen,
				   uint8_t *out, size_t olen)
{
	TEE_Result res = TEE_SUCCESS;

	if (!out)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!add && alen)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&g_lock);
	if (!g_state.test_mode || !g_state.instantiated) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	res = drbg_generate(add, alen, out, olen);
out:
	mutex_unlock(&g_lock);
	return res;
}

TEE_Result hash_drbg_test_reseed(const uint8_t *entropy, size_t elen,
				 const uint8_t *add, size_t alen)
{
	TEE_Result res = TEE_SUCCESS;

	if (!entropy)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!add && alen)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&g_lock);
	if (!g_state.test_mode || !g_state.instantiated) {
		res = TEE_ERROR_BAD_STATE;
		goto out;
	}
	res = drbg_reseed(entropy, elen, add, alen);
out:
	mutex_unlock(&g_lock);
	return res;
}

TEE_Result hash_drbg_test_get_state(uint64_t *counter, uint8_t *V,
				    size_t vlen, uint8_t *C, size_t clen)
{
	if (!counter || !V || !C)
		return TEE_ERROR_BAD_PARAMETERS;
	if (vlen < HASH_DRBG_SEED_LEN || clen < HASH_DRBG_SEED_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&g_lock);
	*counter = g_state.reseed_counter;
	memcpy(V, g_state.V, HASH_DRBG_SEED_LEN);
	memcpy(C, g_state.C, HASH_DRBG_SEED_LEN);
	mutex_unlock(&g_lock);

	return TEE_SUCCESS;
}

#endif /* CFG_QCOM_HASH_DRBG_KAT */
