// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <string.h>

#include "pas.h"

#define PTA_NAME	"pta.qcom.pas"

static struct qcom_pas_data wpss_dsp_data = {
	.pas_id = PAS_ID_WPSS,
	.base.pa = WPSS_BASE,
	.size = WPSS_SIZE,
	.clk_group = QCOM_CLKS_WPSS,
};

static struct qcom_pas_data turing_dsp_data = {
	.pas_id = PAS_ID_TURING,
	.base.pa = TURING_BASE,
	.size = TURING_SIZE,
	.clk_group = QCOM_CLKS_TURING,
};

static TEE_Result qcom_pas_is_supported(uint32_t pt,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("invoked with pas_id: %d", params[0].value.a);

	if (params[0].value.a != PAS_ID_WPSS &&
	    params[0].value.a != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
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

	DMSG("invoked with pas_id: %d", params[0].value.a);
	/* Capabilities flags reserved for future use */
	params[1].value.a = 0;

	return TEE_SUCCESS;
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

	DMSG("invoked with pas_id: %d", params[0].value.a);

	if (params[0].value.a != PAS_ID_WPSS &&
	    params[0].value.a != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

static TEE_Result qcom_pas_mem_setup(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct qcom_pas_data *data = NULL;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("invoked with pas_id: %d", params[0].value.a);

	switch (params[0].value.a) {
	case PAS_ID_WPSS:
		data = &wpss_dsp_data;
		break;
	case PAS_ID_TURING:
		data = &turing_dsp_data;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	data->fw_size = params[0].value.b;
	data->fw_base = params[1].value.a;
	data->fw_base |= SHIFT_U64(params[1].value.b, 32);

	return TEE_SUCCESS;
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

	DMSG("invoked with pas_id: %d", params[0].value.a);

	if (params[0].value.a != PAS_ID_WPSS &&
	    params[0].value.a != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return pas_get_resource_table(params[0].value.a,
				      params[1].memref.buffer,
				      &params[1].memref.size);
}

static TEE_Result
qcom_pas_set_remote_state(uint32_t pt,
			  TEE_Param params[TEE_NUM_PARAMS]__maybe_unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("invoked with pas_id: %d", params[0].value.a);

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result qcom_pas_auth_and_reset(uint32_t pt,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_SUCCESS;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("invoked with pas_id: %d", params[0].value.a);

	switch (params[0].value.a) {
	case PAS_ID_WPSS:
		if (!wpss_dsp_data.fw_base)
			return TEE_ERROR_NO_DATA;

		res = qcom_clock_enable(wpss_dsp_data.clk_group);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to enable clocks: %d", res);
			return res;
		}

		return wpss_fw_start(&wpss_dsp_data);
	case PAS_ID_TURING:
		if (!turing_dsp_data.fw_base)
			return TEE_ERROR_NO_DATA;

		res = qcom_clock_enable(turing_dsp_data.clk_group);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to enable clocks: %d", res);
			return res;
		}

		return compute_fw_start(&turing_dsp_data);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result
qcom_pas_shutdown(uint32_t pt,
		  TEE_Param params[TEE_NUM_PARAMS] __maybe_unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("invoked with pas_id: %d", params[0].value.a);

	switch (params[0].value.a) {
	case PAS_ID_WPSS:
		return wpss_fw_shutdown(&wpss_dsp_data);
	case PAS_ID_TURING:
		return compute_fw_shutdown(&turing_dsp_data);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
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
	uint32_t login = to_ta_session(ts_get_current_session())->clnt_id.login;

	if (login == TEE_LOGIN_REE_KERNEL)
		return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_DENIED;
}

/*
 * TA_FLAG_CONCURRENT disabled:
 *   concurrent operation must be supported by the client.
 */
pseudo_ta_register(.uuid = PTA_QCOM_PAS_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = pta_qcom_pas_invoke_command,
		   .open_session_entry_point = pta_qcom_pas_open_session);
