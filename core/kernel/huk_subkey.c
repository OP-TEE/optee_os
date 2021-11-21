// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <config.h>
#include <crypto/crypto.h>
#include <kernel/huk_subkey.h>
#include <kernel/tee_common_otp.h>
#include <string_ext.h>
#include <tee/tee_fs_key_manager.h>

static TEE_Result mac_usage(void *ctx, uint32_t usage)
{
	return crypto_mac_update(ctx, (const void *)&usage, sizeof(usage));
}

#ifdef CFG_CORE_HUK_SUBKEY_COMPAT
static TEE_Result get_otp_die_id(uint8_t *buffer, size_t len)
{
	static const char pattern[4] = { 'B', 'E', 'E', 'F' };
	size_t i;

	if (IS_ENABLED(CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID))
		return tee_otp_get_die_id(buffer, len);

	for (i = 0; i < len; i++)
		buffer[i] = pattern[i % 4];

	return TEE_SUCCESS;
}

/*
 * This does special treatment for RPMB and SSK key derivations to give
 * the same result as when huk_subkey_derive() wasn't used.
 */
static TEE_Result huk_compat(void *ctx, enum huk_subkey_usage usage)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t chip_id[TEE_FS_KM_CHIP_ID_LENGTH] = { 0 };
	static uint8_t ssk_str[] = "ONLY_FOR_tee_fs_ssk";

	switch (usage) {
	case HUK_SUBKEY_RPMB:
		return TEE_SUCCESS;
	case HUK_SUBKEY_SSK:
		res = get_otp_die_id(chip_id, sizeof(chip_id));
		if (res)
			return res;
		res = crypto_mac_update(ctx, chip_id, sizeof(chip_id));
		if (res)
			return res;
		return crypto_mac_update(ctx, ssk_str, sizeof(ssk_str));
	default:
		return mac_usage(ctx, usage);
	}

}
#endif /*CFG_CORE_HUK_SUBKEY_COMPAT*/

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

	res = crypto_mac_init(ctx, huk.data, sizeof(huk.data));
	if (res)
		goto out;

#ifdef CFG_CORE_HUK_SUBKEY_COMPAT
	res = huk_compat(ctx, usage);
#else
	res = mac_usage(ctx, usage);
#endif
	if (res)
		goto out;

	if (const_data) {
		res = crypto_mac_update(ctx, const_data, const_data_len);
		if (res)
			goto out;
	}

	res = crypto_mac_final(ctx, subkey, subkey_len);
out:
	if (res)
		memzero_explicit(subkey, subkey_len);
	memzero_explicit(&huk, sizeof(huk));
	crypto_mac_free_ctx(ctx);
	return res;
}
