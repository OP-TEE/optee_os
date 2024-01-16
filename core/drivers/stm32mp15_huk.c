// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 * Copyright (c) 2022, Foundries.io Limited
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <drivers/stm32_bsec.h>
#include <kernel/tee_common_otp.h>
#include <mempool.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <string.h>
#include <string_ext.h>

#define HUK_NB_OTP (HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t))

static bool stm32mp15_huk_init;

static TEE_Result stm32mp15_read_uid(uint32_t *uid)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t *q = uid;
	uint32_t otp_idx = 0;
	size_t __maybe_unused sz = 0;
	uint8_t __maybe_unused offset = 0;

	ret = stm32_bsec_find_otp_in_nvmem_layout("uid_otp", &otp_idx, &offset,
						  &sz);
	if (ret)
		return ret;
	assert(sz == 3 * 32);
	assert(offset == 0);

	/*
	 * Shadow memory for UID words might not be locked: to guarante that
	 * the final values are read we must lock them.
	 */
	if (stm32_bsec_set_sw_lock(otp_idx) ||
	    stm32_bsec_shadow_read_otp(q++, otp_idx))
		return TEE_ERROR_GENERIC;

	if (stm32_bsec_set_sw_lock(otp_idx + 1) ||
	    stm32_bsec_shadow_read_otp(q++, otp_idx + 1))
		return TEE_ERROR_GENERIC;

	if (stm32_bsec_set_sw_lock(otp_idx + 2) ||
	    stm32_bsec_shadow_read_otp(q++, otp_idx + 2))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result stm32mp15_read_otp(uint32_t otp, uint32_t *key, bool *locked)
{
	bool tmp = true;
	uint32_t state = 0;

	if (stm32_bsec_get_state(&state))
		panic();

	if (state != BSEC_STATE_SEC_CLOSED) {
		/*
		 * When the device is not closed, the shadow memory for these
		 * words might not be locked: check and report them
		 */
		if (stm32_bsec_read_permanent_lock(otp, &tmp))
			return TEE_ERROR_GENERIC;

		if (tmp && stm32_bsec_read_sw_lock(otp, &tmp))
			return TEE_ERROR_GENERIC;
	}

	if (stm32_bsec_shadow_read_otp(key, otp))
		return TEE_ERROR_GENERIC;

	*locked = *locked && tmp;

	return TEE_SUCCESS;
}

/*
 *  AES-GCM: nonce must be unique per message and key.
 *
 *  This function always uses the same key - once its locked - with the same
 *  unique message hence the nonce can be any constant.
 */
static TEE_Result aes_gcm_encrypt_uid(uint8_t *key, size_t key_len,
				      uint8_t *out, size_t *out_len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	const uint8_t nonce[12] = { 0x55 };
	uint32_t uid[4] = { 0 };
	uint8_t tag[16] = { 0 };
	size_t nonce_len = sizeof(nonce);
	size_t tag_len = sizeof(tag);
	size_t uid_len = sizeof(uid);
	void *ctx = NULL;

	ret = stm32mp15_read_uid(uid);
	if (ret)
		goto out;

	ret = crypto_authenc_alloc_ctx(&ctx, TEE_ALG_AES_GCM);
	if (ret)
		goto out;

	ret = crypto_authenc_init(ctx, TEE_MODE_ENCRYPT, key, key_len, nonce,
				  nonce_len, TEE_AES_BLOCK_SIZE, 0, uid_len);
	if (ret)
		goto out_free_ctx;

	ret = crypto_authenc_enc_final(ctx, (uint8_t *)uid, sizeof(uid),
				       out, out_len, tag, &tag_len);
	if (ret)
		goto out_free_ctx;

	crypto_authenc_final(ctx);
out_free_ctx:
	crypto_authenc_free_ctx(ctx);
out:
	if (ret)
		memzero_explicit(out, *out_len);

	return ret;
}

static __maybe_unused TEE_Result pos_from_dt(uint32_t otp_id[HUK_NB_OTP])
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t otp_start = 0;
	size_t sz = 0;
	uint8_t offset = 0;
	size_t i = 0;

	ret = stm32_bsec_find_otp_in_nvmem_layout("huk-otp", &otp_start,
						  &offset, &sz);
	if (ret)
		return ret;

	if (sz != (HW_UNIQUE_KEY_LENGTH * CHAR_BIT) || offset != 0)
		return TEE_ERROR_SECURITY;

	for (i = 0; i < HUK_NB_OTP; i++)
		otp_id[i] = otp_start + i;

	return TEE_SUCCESS;
}

static TEE_Result get_otp_pos(uint32_t otp_id[HUK_NB_OTP])
{
#ifdef CFG_STM32_HUK_FROM_DT
	return pos_from_dt(otp_id);
#else /* CFG_STM32_HUK_FROM_DT */

	static_assert(CFG_STM32MP15_HUK_BSEC_KEY_0 < STM32MP1_OTP_MAX_ID);
	static_assert(CFG_STM32MP15_HUK_BSEC_KEY_1 < STM32MP1_OTP_MAX_ID);
	static_assert(CFG_STM32MP15_HUK_BSEC_KEY_2 < STM32MP1_OTP_MAX_ID);
	static_assert(CFG_STM32MP15_HUK_BSEC_KEY_3 < STM32MP1_OTP_MAX_ID);

	otp_id[0] = CFG_STM32MP15_HUK_BSEC_KEY_0;
	otp_id[1] = CFG_STM32MP15_HUK_BSEC_KEY_1;
	otp_id[2] = CFG_STM32MP15_HUK_BSEC_KEY_2;
	otp_id[3] = CFG_STM32MP15_HUK_BSEC_KEY_3;

	return TEE_SUCCESS;
#endif /* CFG_STM32_HUK_FROM_DT */
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t otp_key[HUK_NB_OTP] = { };
	uint32_t otp_id[HUK_NB_OTP] = { };
	size_t len = HW_UNIQUE_KEY_LENGTH;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t *key = otp_key;
	bool lock = true;
	size_t i = 0;

	ret = get_otp_pos(otp_id);
	if (ret)
		return ret;

	for (i = 0; i < HUK_NB_OTP; i++) {
		ret = stm32mp15_read_otp(otp_id[i], key++, &lock);
		if (ret)
			goto out;
	}

	if (IS_ENABLED(CFG_STM32MP15_HUK_BSEC_KEY)) {
		static_assert(sizeof(otp_key) == HW_UNIQUE_KEY_LENGTH);
		memcpy(hwkey->data, otp_key, HW_UNIQUE_KEY_LENGTH);
		ret = TEE_SUCCESS;
		goto out;
	}

	if (IS_ENABLED(CFG_STM32MP15_HUK_BSEC_DERIVE_UID)) {
		ret = aes_gcm_encrypt_uid((uint8_t *)otp_key, len, hwkey->data,
					  &len);
		if (len != HW_UNIQUE_KEY_LENGTH)
			ret = TEE_ERROR_GENERIC;
		goto out;
	}

	panic();

out:
	memzero_explicit(otp_key, HW_UNIQUE_KEY_LENGTH);

	if (!ret && !stm32mp15_huk_init) {
		stm32mp15_huk_init = true;
		IMSG("HUK %slocked", lock ? "" : "un");
		DHEXDUMP(hwkey->data, HW_UNIQUE_KEY_LENGTH);
	}

	return ret;
}

