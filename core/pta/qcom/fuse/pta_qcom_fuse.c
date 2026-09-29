// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/qfprom/qfprom.h>
#include <kernel/pseudo_ta.h>
#include <kernel/ts_manager.h>
#include <pta_qcom_fuse.h>
#include <string.h>
#include <tee_api_types.h>

#define TA_PAS_UUID { 0xcff7d191, 0x7ca0, 0x4784, \
		{ 0xaf, 0x13, 0x48, 0x22, 0x3b, 0x9a, 0x4f, 0xbe} }

#define PTA_NAME "qcom_fuse.pta"

static TEE_Result get_secboot_state(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	bool en = false;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_secboot_is_enabled(&en);
	if (res)
		return res;

	params[0].value.a = en;

	return TEE_SUCCESS;
}

static TEE_Result get_root_of_trust(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size < PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE) {
		params[0].memref.size = PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	params[0].memref.size = PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE;

	return qcom_secboot_get_root_of_trust(params[0].memref.buffer,
					      PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE);
}

static TEE_Result get_device_ids(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct qcom_secboot_device_ids ids = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_secboot_get_device_ids(&ids);
	if (res)
		return res;

	params[0].value.a = ids.oem_id;
	params[0].value.b = ids.model_id;
	params[1].value.a = ids.jtag_id;
	params[1].value.b = ids.serial_num;

	return TEE_SUCCESS;
}

static TEE_Result get_soc_hw_version(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t fam_dev = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_secboot_get_soc_hw_version(&fam_dev);
	if (res)
		return res;

	params[0].value.a = fam_dev;
	return TEE_SUCCESS;
}

static TEE_Result get_segment_hash_len(uint32_t param_types,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t hash_len = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_secboot_get_segment_hash_len(params[0].value.a,
						&hash_len);
	if (res)
		return res;

	params[0].value.b = hash_len;
	return TEE_SUCCESS;
}

static TEE_Result get_eku_enforcement_en(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	bool en = false;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_secboot_get_eku_enforcement_en(&en);
	if (res)
		return res;

	params[0].value.a = en;

	return TEE_SUCCESS;
}

static TEE_Result get_use_serial_num(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	bool en = false;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_secboot_is_use_serial_num_enabled(&en);
	if (res)
		return res;

	params[0].value.a = en;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_QCOM_FUSE_GET_SECBOOT_STATE:
		return get_secboot_state(param_types, params);
	case PTA_QCOM_FUSE_GET_ROOT_OF_TRUST:
		return get_root_of_trust(param_types, params);
	case PTA_QCOM_FUSE_GET_DEVICE_IDS:
		return get_device_ids(param_types, params);
	case PTA_QCOM_FUSE_GET_SOC_HW_VERSION:
		return get_soc_hw_version(param_types, params);
	case PTA_QCOM_FUSE_GET_SEGMENT_HASH_LEN:
		return get_segment_hash_len(param_types, params);
	case PTA_QCOM_FUSE_GET_EKU_ENFORCEMENT_EN:
		return get_eku_enforcement_en(param_types, params);
	case PTA_QCOM_FUSE_GET_USE_SERIAL_NUM:
		return get_use_serial_num(param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static TEE_Result open_session(uint32_t pt __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = ts_get_calling_session();
	TEE_UUID ta_uuid = TA_PAS_UUID;
	struct ts_ctx *ctx = NULL;

	if (!s)
		return TEE_ERROR_ACCESS_DENIED;

	ctx = s->ctx;
	if (memcmp(&ctx->uuid, &ta_uuid, sizeof(TEE_UUID)))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_QCOM_FUSE_UUID,
		   .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
