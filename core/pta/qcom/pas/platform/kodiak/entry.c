// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <platform_config.h>
#include <platform_pas.h>
#include <pta_qcom_pas.h>
#include <string.h>

#include "compute.h"
#include "lpass.h"
#include "q6dsp.h"
#include "rtable.h"
#include "video.h"

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

static struct qcom_pas_data lpass_dsp_data = {
	.pas_id = PAS_ID_QDSP6,
	.base.pa = LPASS_BASE,
	.size = LPASS_SIZE,
	.clk_group = QCOM_CLKS_LPASS,
};

static struct qcom_pas_data venus_fw_data = {
	.pas_id = PAS_ID_VENUS,
	.base.pa = IRIS_BASE,
	.size = IRIS_SIZE,
};

TEE_Result qcom_pas_is_supported(uint32_t pt,
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
	    params[0].value.a != PAS_ID_QDSP6 &&
	    params[0].value.a != PAS_ID_VENUS &&
	    params[0].value.a != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

TEE_Result qcom_pas_capabilities(uint32_t pt,
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

TEE_Result qcom_pas_init_image(uint32_t pt,
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
	    params[0].value.a != PAS_ID_QDSP6 &&
	    params[0].value.a != PAS_ID_VENUS &&
	    params[0].value.a != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

TEE_Result qcom_pas_mem_setup(uint32_t pt,
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
	case PAS_ID_QDSP6:
		data = &lpass_dsp_data;
		break;
	case PAS_ID_VENUS:
		data = &venus_fw_data;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	data->fw_size = params[0].value.b;
	data->fw_base = params[1].value.a;
	data->fw_base |= SHIFT_U64(params[1].value.b, 32);

	/* Map the controller */
	if (!data->base.va) {
		data->base.va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_NSEC,
							      data->base.pa,
							      data->size);
		if (!data->base.va)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_pas_get_resource_table(uint32_t pt,
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
	    params[0].value.a != PAS_ID_TURING &&
	    params[0].value.a != PAS_ID_QDSP6)
		return TEE_ERROR_NOT_SUPPORTED;

	return pas_get_resource_table(params[0].value.a,
				      params[1].memref.buffer,
				      &params[1].memref.size);
}

TEE_Result
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

	if (params[0].value.a == PAS_ID_VENUS)
		return venus_fw_set_state(&venus_fw_data, params[0].value.b);

	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result qcom_pas_auth_and_reset(uint32_t pt,
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
	case PAS_ID_QDSP6:
		if (!lpass_dsp_data.fw_base)
			return TEE_ERROR_NO_DATA;

		res = qcom_clock_enable(lpass_dsp_data.clk_group);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to enable clocks: %d", res);
			return res;
		}

		return lpass_fw_start(&lpass_dsp_data);
	case PAS_ID_VENUS:
		if (!venus_fw_data.fw_base)
			return TEE_ERROR_NO_DATA;

		return venus_fw_start(&venus_fw_data);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_pas_shutdown(uint32_t pt,
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
	case PAS_ID_QDSP6:
		return lpass_fw_shutdown(&lpass_dsp_data);
	case PAS_ID_VENUS:
		return venus_fw_shutdown(&venus_fw_data);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}
