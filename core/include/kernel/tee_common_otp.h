/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __KERNEL_TEE_COMMON_OTP_H
#define __KERNEL_TEE_COMMON_OTP_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>

struct tee_hw_unique_key {
	uint8_t data[HW_UNIQUE_KEY_LENGTH];
};

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey);
int tee_otp_get_die_id(uint8_t *buffer, size_t len);
TEE_Result tee_otp_get_ta_enc_key(uint32_t key_type, uint8_t *buffer,
				  size_t len);

#endif /* __KERNEL_TEE_COMMON_OTP_H */
