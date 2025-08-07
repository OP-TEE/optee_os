/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Pengutronix, Michael Tretter <m.tretter@pengutronix.de>
 */

#ifndef __DRIVERS_ROCKCHIP_OTP_H
#define __DRIVERS_ROCKCHIP_OTP_H

#include <tee_api_types.h>

/*
 * Read the OTP fuses at index
 *
 * @[out]value	destination for the values that are read from the OTP fuses
 * @index	index of the first word to read in 32 bit words
 * @count	number of 32 bit words to read
 */
TEE_Result rockchip_otp_read_secure(uint32_t *value, uint32_t index,
				    uint32_t count);

/*
 * Write the OTP fuses at index
 *
 * @value	pointer to values that are written to the OTP fuses
 * @index	index of the first word to write in 32 bit words
 * @count	number of 32 bit words to write
 */
TEE_Result rockchip_otp_write_secure(const uint32_t *value, uint32_t index,
				     uint32_t count);

#endif /* __DRIVERS_ROCKCHIP_OTP_H */
