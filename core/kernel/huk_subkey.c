// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/huk_subkey.h>
#include <kernel/tee_common_otp.h>

static TEE_Result mac_usage(void *ctx, uint32_t usage)
{
	return crypto_mac_update(ctx, TEE_ALG_HMAC_SHA256,
				 (const void *)&usage, sizeof(usage));
}

TEE_Result huk_subkey_derive(enum huk_subkey_usage usage,
			     const void *const_data, size_t const_data_len,
			     uint8_t *subkey, size_t subkey_len)
{
	void *ctx = NULL;
	struct tee_hw_unique_key huk = { };
	TEE_Result res = TEE_SUCCESS;

	if (subkey_len > HUK_SUBKEY_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!const_data && const_data_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = crypto_mac_alloc_ctx(&ctx, TEE_ALG_HMAC_SHA256);
	if (res)
		return res;

	res = tee_otp_get_hw_unique_key(&huk);
	if (res)
		goto out;

	res = crypto_mac_init(ctx, TEE_ALG_HMAC_SHA256, huk.data,
			      sizeof(huk.data));
	if (res)
		goto out;

	res = mac_usage(ctx, usage);
	if (res)
		goto out;

	if (const_data) {
		res = crypto_mac_update(ctx, TEE_ALG_HMAC_SHA256, const_data,
					const_data_len);
		if (res)
			goto out;
	}

	res = crypto_mac_final(ctx, TEE_ALG_HMAC_SHA256, subkey, subkey_len);
out:
	if (res)
		memset(subkey, 0, subkey_len);
	memset(&huk, 0, sizeof(huk));
	crypto_mac_free_ctx(ctx, TEE_ALG_HMAC_SHA256);
	return res;
}
