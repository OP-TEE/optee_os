// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, 2019, Linaro Limited
 */

#include <assert.h>
#include <inttypes.h>
#include <kernel/tee_common_otp.h>
#include <kernel/huk_subkey.h>
#include <signed_hdr.h>
#include <ta_pub_key.h>

/*
 * Override these in your platform code to really fetch device-unique
 * bits from e-fuses or whatever.
 *
 * The default implementation just sets it to a constant.
 */

__weak TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	memset(&hwkey->data[0], 0, sizeof(hwkey->data));
	return TEE_SUCCESS;
}

__weak int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	if (huk_subkey_derive(HUK_SUBKEY_DIE_ID, NULL, 0, buffer, len))
		return -1;

	return 0;
}

#ifdef CFG_WITH_USER_TA
/*
 * Override this API on your platform to provide TA encryption key as
 * per your security requirements. There can be two options for this key:
 *
 * 1) Unique per device encryption key.
 * 2) Class wide encryption key.
 *
 * The default implementation chooses option (1).
 */
__weak TEE_Result tee_otp_get_ta_enc_key(uint32_t key_type __maybe_unused,
					 uint8_t *buffer, size_t len)
{
	assert(key_type == SHDR_ENC_KEY_DEV_SPECIFIC);

	if (huk_subkey_derive(HUK_SUBKEY_TA_ENC, ta_pub_key_modulus,
			      ta_pub_key_modulus_size, buffer, len))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}
#endif
