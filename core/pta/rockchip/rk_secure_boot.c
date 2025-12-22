// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025, Pengutronix, Michael Tretter <entwicklung@pengutronix.de>
 */

#include <config.h>
#include <drivers/rockchip_otp.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_misc.h>
#include <tee/uuid.h>
#include <utee_defines.h>
#include <stdio.h>
#include <string.h>
#include <platform_config.h>

#include <pta_rk_secure_boot.h>

#define PTA_NAME "rk_secure_boot.pta"

/*
 * Disable simulation to actually fusing the hash into the OTP. Enabling this
 * option is necessary to actually enable secure boot with PTA, but may
 * potentially brick your device.
 */
static const int simulation = IS_ENABLED2(CFG_RK_SECURE_BOOT_SIMULATION);

/*
 * The hash is stored in OTP in little endian. The PTA assumes that OP-TEE is
 * in little endian and may copy the hash from memory to OTP without ensuring
 * the byte order.
 */
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

static inline bool bit_test(uint32_t value, uint32_t bit)
{
	return (value & bit) == bit;
}

#define HASH_STRING_SIZE 88
static char *otp_to_string(uint32_t *otp, size_t otp_size,
			   char *str, size_t str_size)
{
	if (otp_size != 8 || str_size != HASH_STRING_SIZE)
		return NULL;

	snprintf(str, str_size,
		 "0x%" PRIx32 " 0x%" PRIx32 " 0x%" PRIx32 " 0x%" PRIx32
		 " 0x%" PRIx32 " 0x%" PRIx32 " 0x%" PRIx32 " 0x%" PRIx32,
		 otp[0], otp[1], otp[2], otp[3],
		 otp[4], otp[5], otp[6], otp[7]);

	return str;
}

static TEE_Result write_key_size(uint32_t key_size_bits)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t status = 0;

	IMSG("Setting key size to %d", key_size_bits);

	switch (key_size_bits) {
	case 4096:
		status |= ROCKCHIP_OTP_SECURE_BOOT_STATUS_RSA4096;

		res = rockchip_otp_write_secure(&status,
				ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
		if (res != TEE_SUCCESS)
			return res;

		res = rockchip_otp_read_secure(&status,
				ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
		if (res != TEE_SUCCESS)
			return res;
		if (!bit_test(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_RSA4096))
			return TEE_ERROR_GENERIC;
		break;
	case 2048:
		/* Nothing to do */
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	return res;
}

static TEE_Result write_hash(uint32_t *hash, size_t size)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t tmp[ROCKCHIP_OTP_RSA_HASH_SIZE];
	char str[HASH_STRING_SIZE];

	if (size != ROCKCHIP_OTP_RSA_HASH_SIZE)
		return TEE_ERROR_GENERIC;

	IMSG("Burning hash %s", otp_to_string(hash, size, str, sizeof(str)));

	res = rockchip_otp_write_secure(hash,
					ROCKCHIP_OTP_RSA_HASH_INDEX,
					ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = rockchip_otp_read_secure(tmp,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res != TEE_SUCCESS)
		return res;
	if (memcmp(tmp, hash, sizeof(tmp)) != 0) {
		EMSG("Failed to burn hash. OTP is %s",
		     otp_to_string(tmp, ARRAY_SIZE(tmp), str, sizeof(str)));
		return res;
	}

	return res;
}

static TEE_Result get_info(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pta_rk_secure_boot_info *info = NULL;
	uint32_t status = 0;
	uint32_t hash[ROCKCHIP_OTP_RSA_HASH_SIZE];
	char str[HASH_STRING_SIZE];

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, typeof(*info)))
		return TEE_ERROR_BAD_PARAMETERS;

	info = params[0].memref.buffer;
	if (!info || params[0].memref.size != sizeof(*info))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(info, 0, sizeof(*info));

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res)
		return res;

	res = rockchip_otp_read_secure(hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;

	DMSG("Current hash: %s",
	     otp_to_string(hash, ARRAY_SIZE(hash), str, sizeof(str)));

	info->enabled = bit_test(status,
				 ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE);
	info->simulation = simulation;
	memcpy(info->hash.value, hash, sizeof(info->hash.value));

	return TEE_SUCCESS;
}

static TEE_Result burn_hash(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	struct pta_rk_secure_boot_hash *hash;
	size_t hash_sz;
	uint32_t status;
	uint32_t new_hash[ROCKCHIP_OTP_RSA_HASH_SIZE];
	uint32_t old_hash[ROCKCHIP_OTP_RSA_HASH_SIZE];
	uint32_t key_size_bits;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	hash = params[0].memref.buffer;
	hash_sz = params[0].memref.size;
	if (!hash || hash_sz != sizeof(*hash))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(new_hash, hash->value, sizeof(new_hash));

	key_size_bits = params[1].value.a;
	if (key_size_bits != 4096 && key_size_bits != 2048) {
		EMSG("Invalid key size: %d", key_size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = rockchip_otp_read_secure(old_hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	if (memcmp(old_hash, new_hash, sizeof(new_hash)) != 0) {
		char str[HASH_STRING_SIZE];

		EMSG("Refusing to burn hash %s",
		     otp_to_string(new_hash, ARRAY_SIZE(new_hash),
				   str, sizeof(str)));
		EMSG("OTP hash is %s",
		     otp_to_string(old_hash, ARRAY_SIZE(old_hash),
				   str, sizeof(str)));

		return res;
	}

	/*
	 * Check if secure boot is already enabled after verifying the
	 * parameters for reporting the correct error if the command would
	 * result in the same state as the already fused board.
	 */
	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res != TEE_SUCCESS)
		return res;
	if (bit_test(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE)) {
		DMSG("Secure boot already enabled");
		return TEE_SUCCESS;
	}

	if (simulation) {
		char str[HASH_STRING_SIZE];

		IMSG("Simulation mode: Skip burning hash %s, key size %d",
		     otp_to_string(new_hash, ARRAY_SIZE(new_hash),
				   str, sizeof(str)),
		     key_size_bits);

		return TEE_SUCCESS;
	}

	res = write_hash(new_hash, ARRAY_SIZE(new_hash));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to write hash");
		return res;
	}

	res = write_key_size(key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to write key size");
		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result lockdown_device(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t status;
	uint32_t hash[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	uint32_t zero[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = rockchip_otp_read_secure(hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res != TEE_SUCCESS)
		return res;
	if (memcmp(zero, hash, sizeof(hash)) == 0) {
		EMSG("OTP hash is all zeros. Refuse lockdown.");
		return TEE_ERROR_GENERIC;
	}

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res != TEE_SUCCESS)
		return res;
	if (bit_test(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE)) {
		DMSG("Secure boot already enabled");
		return TEE_SUCCESS;
	}

	status = ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE;

	if (simulation) {
		IMSG("Simulation mode: Skip writing status: %" PRIx32,
		     status);
		return TEE_SUCCESS;
	}

	IMSG("Writing secure boot status: %" PRIx32, status);
	res = rockchip_otp_write_secure(&status,
					ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
					ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res != TEE_SUCCESS)
		return res;

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res != TEE_SUCCESS)
		return res;
	if (bit_test(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE)) {
		EMSG("Failed to write secure boot status");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_Result res2 = TEE_ERROR_GENERIC;
	TEE_Param bparams[TEE_NUM_PARAMS] = { };
	TEE_Param *eparams = NULL;

	res = to_bounce_params(param_types, params, bparams, &eparams);
	if (res)
		return res;

	switch (cmd_id) {
	case PTA_RK_SECURE_BOOT_GET_INFO:
		res = get_info(param_types, eparams);
		break;
	case PTA_RK_SECURE_BOOT_BURN_HASH:
		res = burn_hash(param_types, eparams);
		break;
	case PTA_RK_SECURE_BOOT_LOCKDOWN_DEVICE:
		res = lockdown_device(param_types, eparams);
		break;
	default:
		break;
	}

	res2 = from_bounce_params(param_types, params, bparams, eparams);
	if (!res && res2)
		res = res2;

	return res;
}

pseudo_ta_register(.uuid = PTA_RK_SECURE_BOOT_UUID,
		   .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
