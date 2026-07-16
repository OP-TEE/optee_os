// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <kernel/pseudo_ta.h>
#include <kernel/ts_manager.h>
#include <platform_pas.h>
#include <pta_qcom_pas.h>
#include <string.h>
#include <util.h>

#define PTA_NAME	"pta.qcom.pas"

#define TA_PAS_UUID { 0xcff7d191, 0x7ca0, 0x4784, \
		{ 0xaf, 0x13, 0x48, 0x22, 0x3b, 0x9a, 0x4f, 0xbe} }

static TEE_Result qcom_pas_is_supported(uint32_t pt,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_is_supported(params[0].value.a);
}

static TEE_Result qcom_pas_capabilities(uint32_t pt,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	/* Capabilities flags reserved for future use */
	params[1].value.a = 0;
	return pas_platform_capabilities(params[0].value.a);
}

static TEE_Result qcom_pas_init_image(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_init_image(params[0].value.a);
}

static TEE_Result qcom_pas_mem_setup(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_mem_setup(params[0].value.a, params[0].value.b,
				      params[1].value.a, params[1].value.b);
}

static TEE_Result qcom_pas_get_resource_table(uint32_t pt,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_get_resource_table(params[0].value.a,
					       params[1].memref.buffer,
					       &params[1].memref.size);
}

static TEE_Result
qcom_pas_set_remote_state(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_set_remote_state(params[0].value.a,
					     params[0].value.b);
}

static TEE_Result qcom_pas_auth_and_reset(uint32_t pt,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_auth_and_reset(params[0].value.a);
}

static TEE_Result
qcom_pas_shutdown(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("invoked with pas_id: %u", params[0].value.a);

	return pas_platform_shutdown(params[0].value.a);
}

static TEE_Result
qcom_pas_verify_image(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT);
	/*
	 * params[2].memref: packed [metadata | hash_table] buffer
	 * params[3].value.a: hash_size
	 * params[3].value.b: metadata_size (= offset of hash_table in buf)
	 */
	const uint8_t *buf = NULL;
	size_t metadata_size = 0;
	size_t hash_table_size = 0;
	paddr_t fw_base = 0;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[2].memref.buffer || !params[2].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	metadata_size = params[3].value.b;
	if (!metadata_size || metadata_size >= params[2].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = params[2].memref.buffer;
	hash_table_size = params[2].memref.size - metadata_size;

	fw_base = reg_pair_to_64(params[1].value.b, params[1].value.a);

	DMSG("invoked with pas_id: %u md=%zu ht=%zu",
	     params[0].value.a, metadata_size, hash_table_size);

	return pas_platform_verify_image(params[0].value.a, params[0].value.b,
					 fw_base,
					 buf, metadata_size,
					 buf + metadata_size, hash_table_size,
					 params[3].value.a);
}

static TEE_Result pta_qcom_pas_invoke_command(void *session __unused,
					      uint32_t cmd_id,
					      uint32_t param_types,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_QCOM_PAS_IS_SUPPORTED:
		return qcom_pas_is_supported(param_types, params);
	case PTA_QCOM_PAS_CAPABILITIES:
		return qcom_pas_capabilities(param_types, params);
	case PTA_QCOM_PAS_INIT_IMAGE:
		return qcom_pas_init_image(param_types, params);
	case PTA_QCOM_PAS_MEM_SETUP:
		return qcom_pas_mem_setup(param_types, params);
	case PTA_QCOM_PAS_GET_RESOURCE_TABLE:
		return qcom_pas_get_resource_table(param_types, params);
	case PTA_QCOM_PAS_AUTH_AND_RESET:
		return qcom_pas_auth_and_reset(param_types, params);
	case PTA_QCOM_PAS_SET_REMOTE_STATE:
		return qcom_pas_set_remote_state(param_types, params);
	case PTA_QCOM_PAS_SHUTDOWN:
		return qcom_pas_shutdown(param_types, params);
	case PTA_QCOM_PAS_VERIFY_IMAGE:
		return qcom_pas_verify_image(param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Pseudo Trusted Application entry points
 */
static TEE_Result
pta_qcom_pas_open_session(uint32_t pt __unused,
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

/*
 * TA_FLAG_CONCURRENT disabled:
 *   concurrent operation must be supported by the client.
 */
pseudo_ta_register(.invoke_command_entry_point = pta_qcom_pas_invoke_command,
		   .open_session_entry_point = pta_qcom_pas_open_session,
		   .flags = PTA_DEFAULT_FLAGS,
		   .uuid = PTA_QCOM_PAS_UUID,
		   .name = PTA_NAME);
