// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <inttypes.h>
#include <kernel/tee_common_otp.h>

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
	static const char pattern[4] = { 'B', 'E', 'E', 'F' };
	size_t i;

	for (i = 0; i < len; i++)
		buffer[i] = pattern[i % 4];

	return 0;
}
