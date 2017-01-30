/*
 * Copyright (c) 2015, Linaro Limited
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

#include <inttypes.h>
#include <kernel/tee_common_otp.h>

uint8_t secure_device_id[MAX_SECURE_DEVICE_ID_LEN];
size_t secure_device_id_len;

/*
 * Override these in your platform code to really fetch device-unique
 * bits from e-fuses or whatever.
 *
 * The default implementation just sets it to a constant.
 *
 * If your bootloader passes OP-TEE a DTB, then if it has a property
 * firmware/optee/secure-device-id, the data found in there is
 * used to generate a pseudo-id.  This may have been sourced from,
 * eg, eMMC CID serial number that is specific to the individual
 * PCB, if not the SoC.
 */

__weak void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	const uint8_t *p = secure_device_id;
	size_t n;

	if (!secure_device_id_len) {
		memset(hwkey->data, 0, sizeof(hwkey->data));
		return;
	}

	for (n = 0; n < sizeof(hwkey->data); n++)
		hwkey->data[n] = p[n % secure_device_id_len] ^ 0xff;
}

__weak int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	static const uint8_t default_pattern[] = { 'B', 'E', 'E', 'F' };
	size_t plen = sizeof(default_pattern);
	const uint8_t *p = default_pattern;
	size_t n;

	if (secure_device_id_len) {
		p = (const uint8_t *)&secure_device_id;
		plen = secure_device_id_len;
	}

	for (n = 0; n < len; n++)
		*buffer++ = p[n % plen];

	return 0;
}
