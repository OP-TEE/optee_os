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
 * The hash is stored in OTP in little endian. The PTA assumes that OP-TEE is
 * in little endian and may copy the hash from memory to OTP without ensuring
 * the byte order.
 */
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

static inline bool test_bit_mask(uint32_t value, uint32_t mask)
{
	return (value & mask) == mask;
}

#define HASH_STRING_SIZE 88
static_assert(ROCKCHIP_OTP_RSA_HASH_SIZE == 8);
static __maybe_unused char *otp_to_string(uint32_t *otp,
					  char *str, size_t str_size)
{
	snprintf(str, str_size,
		 "0x%"PRIx32" 0x%"PRIx32" 0x%"PRIx32" 0x%"PRIx32
		 " 0x%"PRIx32" 0x%"PRIx32" 0x%"PRIx32" 0x%"PRIx32,
		 otp[0], otp[1], otp[2], otp[3],
		 otp[4], otp[5], otp[6], otp[7]);

	return str;
}

static TEE_Result write_key_size(uint32_t key_size_bits)
{
	uint32_t idx = ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX;
	uint32_t sz = ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE;
	TEE_Result res = TEE_SUCCESS;
	uint32_t status = 0;

	IMSG("Setting key size to %"PRId32, key_size_bits);

	switch (key_size_bits) {
	case 4096:
		status |= ROCKCHIP_OTP_SECURE_BOOT_STATUS_RSA4096;

		res = rockchip_otp_write_secure(&status, idx, sz);
		if (res)
			return res;

		res = rockchip_otp_read_secure(&status, idx, sz);
		if (res)
			return res;
		if (!test_bit_mask(status,
				   ROCKCHIP_OTP_SECURE_BOOT_STATUS_RSA4096))
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
	char __maybe_unused str[HASH_STRING_SIZE] = {};
	uint32_t tmp[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	TEE_Result res = TEE_SUCCESS;

	if (size != ROCKCHIP_OTP_RSA_HASH_SIZE)
		return TEE_ERROR_GENERIC;

	IMSG("Burning hash %s", otp_to_string(hash, str, sizeof(str)));

	res = rockchip_otp_write_secure(hash,
					ROCKCHIP_OTP_RSA_HASH_INDEX,
					ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;

	res = rockchip_otp_read_secure(tmp,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	if (memcmp(tmp, hash, sizeof(tmp))) {
		EMSG("Failed to burn hash. OTP is %s",
		     otp_to_string(tmp, str, sizeof(str)));
		return res;
	}

	return res;
}

static TEE_Result get_info(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t hash[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	char __maybe_unused str[HASH_STRING_SIZE] = {};
	struct pta_rk_secure_boot_info *info = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t status = 0;

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

	DMSG("Current hash: %s", otp_to_string(hash, str, sizeof(str)));

	info->enabled = test_bit_mask(status,
				      ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE);
	info->simulation = IS_ENABLED(CFG_RK_SECURE_BOOT_SIMULATION);
	memcpy(info->hash.value, hash, sizeof(info->hash.value));

	return TEE_SUCCESS;
}

static TEE_Result burn_hash(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t new_hash[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	uint32_t old_hash[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	char __maybe_unused str[HASH_STRING_SIZE] = {};
	struct pta_rk_secure_boot_hash *hash = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t key_size_bits = 0;
	uint32_t status = 0;
	size_t hash_sz = 0;

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
		EMSG("Invalid key size: %"PRId32, key_size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = rockchip_otp_read_secure(old_hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	if (memcmp(old_hash, new_hash, sizeof(new_hash))) {
		EMSG("Refusing to burn hash %s",
		     otp_to_string(new_hash, str, sizeof(str)));
		EMSG("OTP hash is %s",
		     otp_to_string(old_hash, str, sizeof(str)));
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
	if (res)
		return res;
	if (test_bit_mask(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE)) {
		DMSG("Secure boot already enabled");
		return TEE_SUCCESS;
	}

	if (IS_ENABLED(CFG_RK_SECURE_BOOT_SIMULATION)) {
		IMSG("Simulation mode: Skip burning hash %s, key size %"PRId32,
		     otp_to_string(new_hash, str, sizeof(str)), key_size_bits);
		return TEE_SUCCESS;
	}

	res = write_hash(new_hash, ARRAY_SIZE(new_hash));
	if (res) {
		EMSG("Failed to write hash");
		return res;
	}

	res = write_key_size(key_size_bits);
	if (res) {
		EMSG("Failed to write key size");
		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result lockdown_device(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	uint32_t hash[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	uint32_t zero[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t status = 0;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = rockchip_otp_read_secure(hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	if (!memcmp(zero, hash, sizeof(hash))) {
		EMSG("OTP hash is all zeros. Refuse lockdown.");
		return TEE_ERROR_GENERIC;
	}

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res)
		return res;
	if (test_bit_mask(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE)) {
		DMSG("Secure boot already enabled");
		return TEE_SUCCESS;
	}

	status = ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE;

	if (IS_ENABLED(CFG_RK_SECURE_BOOT_SIMULATION)) {
		IMSG("Simulation mode: Skip writing status: %"PRIx32,
		     status);
		return TEE_SUCCESS;
	}

	IMSG("Writing secure boot status: %"PRIx32, status);
	res = rockchip_otp_write_secure(&status,
					ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
					ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res)
		return res;

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res)
		return res;
	if (test_bit_mask(status, ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE)) {
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
	TEE_Param bparams[TEE_NUM_PARAMS] = { };
	TEE_Result res2 = TEE_ERROR_GENERIC;
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
