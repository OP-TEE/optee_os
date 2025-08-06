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
#include <string.h>
#include <platform_config.h>

#include <pta_rk_secure_boot.h>

#define PTA_NAME "rk_secure_boot.pta"

static void u32_to_bytes(uint32_t u32, uint8_t *bytes)
{
	size_t i;

	for (i = 0; i < sizeof(u32); i++)
		*(bytes + i) = (uint8_t)(u32 >> (i * 8));
}

static void bytes_to_u32(uint8_t *bytes, uint32_t *u32)
{
	size_t i;

	*u32 = 0;
	for (i = 0; i < sizeof(u32); i++)
		*u32 += (uint32_t)*(bytes + i) << (i * 8);
}

static void print_hash(const char *prefix, uint32_t *hash)
{
	/* Prevent unused parameter warnings */
	(void)prefix;
	(void)hash;

	EMSG("%s0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x\n",
	     prefix,
	     hash[0], hash[1], hash[2], hash[3],
	     hash[4], hash[5], hash[6], hash[7]);
}

static bool secure_boot_status_enabled(uint32_t status)
{
	return (status & ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE) ==
		ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE;
}

static TEE_Result get_info(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pta_rk_secure_boot_info *info = NULL;
	uint32_t status = 0;
	uint32_t hash[ROCKCHIP_OTP_RSA_HASH_SIZE];
	size_t i;

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

	info->enabled = secure_boot_status_enabled(status);
	for (i = 0; i < ARRAY_SIZE(hash); i++)
		u32_to_bytes(hash[i], &info->hash.value[i * sizeof(uint32_t)]);
#if !defined(SECURE_BOOT_ENABLE_DANGEROUS)
	info->simulation = 1;
#else
	info->simulation = 0;
#endif

	return TEE_SUCCESS;
}

/* Compare the hashes and return the number of identical bytes */
static size_t hash_cmp(uint32_t *a, uint32_t *b, size_t s)
{
	size_t i;

	for (i = 0; i < s; i++) {
		if (b && a[i] == b[i]) {
			continue;
		} else if (a[i] == 0x0) {
			break;
		} else if (!b) {
			continue;
		} else {
			EMSG("Burned hash differs from new hash");
			return TEE_ERROR_GENERIC;
		}
	}

	return i;
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
	size_t i;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	hash = params[0].memref.buffer;
	hash_sz = params[0].memref.size;
	if (!hash || hash_sz != sizeof(*hash))
		return TEE_ERROR_BAD_PARAMETERS;

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res)
		return res;
	if (secure_boot_status_enabled(status))
		return TEE_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(new_hash); i++)
		bytes_to_u32(&hash->value[i * sizeof(uint32_t)], &new_hash[i]);

	print_hash("Burning new hash ", new_hash);
	res = rockchip_otp_read_secure(old_hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	i = hash_cmp(old_hash, new_hash, ARRAY_SIZE(new_hash));
	if (i == TEE_ERROR_GENERIC) {
		print_hash("Refuse to write new hash. Burned hash is ",
			   old_hash);
		return TEE_ERROR_GENERIC;
	}

#if !defined(SECURE_BOOT_ENABLE_DANGEROUS)
	print_hash("Skip burning new hash ", new_hash);
#else
	print_hash("Burning new hash ", new_hash);
	res = rockchip_otp_write_secure(new_hash,
					ROCKCHIP_OTP_RSA_HASH_INDEX + i,
					ROCKCHIP_OTP_RSA_HASH_SIZE - i);
	if (res)
		return res;

	res = rockchip_otp_read_secure(old_hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	if (hash_cmp(old_hash, new_hash, ARRAY_SIZE(new_hash)) !=
	    ARRAY_SIZE(new_hash)) {
		print_hash("Failed to burn hash. Burned hash is ", old_hash);
		return TEE_ERROR_GENERIC;
	}
#endif

	/* TODO Pass RSA key length as an argument */
	status = ROCKCHIP_OTP_SECURE_BOOT_STATUS_RSA4096;
#if !defined(SECURE_BOOT_ENABLE_DANGEROUS)
	IMSG("Skip writing RSA4096 enable bit: %x", status);
#else
	IMSG("Writing RSA4096 enable bit: %x", status);
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
#endif

	return TEE_SUCCESS;
}

static TEE_Result lockdown_device(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t status;
	uint32_t hash[ROCKCHIP_OTP_RSA_HASH_SIZE] = {};

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = rockchip_otp_read_secure(&status,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_INDEX,
				       ROCKCHIP_OTP_SECURE_BOOT_STATUS_SIZE);
	if (res)
		return res;
	if (secure_boot_status_enabled(status))
		return TEE_SUCCESS;

	res = rockchip_otp_read_secure(hash,
				       ROCKCHIP_OTP_RSA_HASH_INDEX,
				       ROCKCHIP_OTP_RSA_HASH_SIZE);
	if (res)
		return res;
	if (hash_cmp(hash, NULL, ARRAY_SIZE(hash) < ARRAY_SIZE(hash))) {
		print_hash("Hash not burned yet. Burned hash is ", hash);
		return TEE_ERROR_GENERIC;
	}

	status = ROCKCHIP_OTP_SECURE_BOOT_STATUS_ENABLE;
#if !defined(SECURE_BOOT_ENABLE_DANGEROUS)
	IMSG("Skip writing secure boot enable bit: %x", status);
#else
	IMSG("Writing secure boot enable bit: %x", status);
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
	if (secure_boot_status_enabled(status)) {
		EMSG("Failed to enable secure boot");
		return TEE_ERROR_GENERIC;
	}
#endif

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
