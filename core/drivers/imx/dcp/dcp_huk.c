// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <drivers/imx/dcp.h>
#include <kernel/tee_common_otp.h>
#include <local.h>
#include <trace.h>

#define HUK_MESSAGE_NULL_BYTE 0
#define NB_ITERATION_HUK      1
#define HUK_SIZE_BITS	      128

/* State of the generated HUK */
enum dcp_huk_state {
	DCP_HUK_EMPTY = 0,
	DCP_HUK_GENERATED,
	DCP_HUK_ERROR,
};

/* Information about HUK */
static struct {
	enum dcp_huk_state state;
	uint8_t data[HW_UNIQUE_KEY_LENGTH];
} dcp_huk = { .state = DCP_HUK_EMPTY };

/*
 * Generate Hardware Unique Key using the Data Co-Processor (DCP) AES128-CMAC
 * cryptographic operation
 * Follow dcp_aes_cmac() message format
 *
 * @hwkey   [out] Hardware Unique Key private data
 */
static TEE_Result dcp_generate_huk(struct tee_hw_unique_key *hwkey)
{
	struct dcp_cipher_init init = {
		.key_mode = DCP_OTP,
		.mode = DCP_ECB,
		.op = DCP_ENCRYPT,
	};
	uint8_t content[DCP_AES128_BLOCK_SIZE] = { NB_ITERATION_HUK,
						   'h',
						   'u',
						   'k',
						   HUK_MESSAGE_NULL_BYTE,
						   'o',
						   'p',
						   't',
						   'e',
						   'e',
						   'o',
						   's',
						   'd',
						   'c',
						   'p',
						   HUK_SIZE_BITS };

	return dcp_cmac(&init, content, DCP_AES128_BLOCK_SIZE, hwkey->data);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!hwkey || !hwkey->data) {
		EMSG("HUK generation failed, hwkey structure is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = dcp_init();
	if (ret != TEE_SUCCESS) {
		dcp_huk.state = DCP_HUK_ERROR;
		return ret;
	}

	if (dcp_huk.state == DCP_HUK_EMPTY) {
		ret = dcp_generate_huk(hwkey);
		if (ret != TEE_SUCCESS) {
			dcp_huk.state = DCP_HUK_ERROR;
		} else {
			memcpy(dcp_huk.data, hwkey->data, HW_UNIQUE_KEY_LENGTH);
			dcp_huk.state = DCP_HUK_GENERATED;
		}
	} else if (dcp_huk.state == DCP_HUK_GENERATED) {
		memcpy(hwkey->data, dcp_huk.data, HW_UNIQUE_KEY_LENGTH);
		ret = TEE_SUCCESS;
	} else {
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}
