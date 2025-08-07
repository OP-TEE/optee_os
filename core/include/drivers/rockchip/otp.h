/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Pengutronix, Michael Tretter <m.tretter@pengutronix.de>
 */

#ifndef __DRIVERS_ROCKCHIP_OTP_H
#define __DRIVERS_ROCKCHIP_OTP_H

#include <tee_api_types.h>

#define SECURE_BOOT_STATUS_INDEX	0x8
#define SECURE_BOOT_STATUS_LENGTH	1
#define SECURE_BOOT_STATUS_ENABLE	0xff
#define SECURE_BOOT_STATUS_RSA4096	0x3000

#define HW_UNIQUE_KEY_INDEX		0x104

#define RSA_HASH_INDEX			0x270
#define RSA_HASH_LENGTH			8

/*
 * Read the OTP fuses at index
 *
 * @[out]value	destination of the OTP fuse values
 * @index	index of the first word to read in 32 bit words
 * @count 	number of 32 bit words to read
 */
TEE_Result tee_otp_read_secure(uint32_t *value, uint32_t index,
			       uint32_t count);

/*
 * Write the OTP fuses at index
 *
 * @value	value that is written to the OTP fuse
 * @index	index of the first word to write in 32 bit words
 * @count 	number of 32 bit words to write
 */
TEE_Result tee_otp_write_secure(const uint32_t *value, uint32_t index,
				uint32_t count);

#endif /* __DRIVERS_ROCKCHIP_OTP_H */
