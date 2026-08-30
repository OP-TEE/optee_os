// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_fuse.h>
#include <pta_qcom_fuse.h>
#include <string.h>
#include <tee_internal_api.h>

static TEE_TASessionHandle fuse_session;

TEE_Result pas_fuse_open(void)
{
	static const TEE_UUID fuse_uuid = PTA_QCOM_FUSE_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (fuse_session != TEE_HANDLE_NULL)
		return TEE_SUCCESS;

	res = TEE_OpenTASession(&fuse_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&fuse_session, NULL);
	if (res)
		EMSG("PAS fuse: cannot open fuse PTA: %#"PRIx32, res);

	return res;
}

void pas_fuse_close(void)
{
	if (fuse_session == TEE_HANDLE_NULL)
		return;

	TEE_CloseTASession(fuse_session);
	fuse_session = TEE_HANDLE_NULL;
}

static TEE_Result fuse_pta_invoke(uint32_t cmd, uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	if (fuse_session == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	return TEE_InvokeTACommand(fuse_session, TEE_TIMEOUT_INFINITE, cmd,
				   param_types, params, NULL);
}

TEE_Result pas_fuse_get_secboot_state(enum pas_secboot_state *state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_SECBOOT_STATE, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read secboot state: %#"PRIx32, res);
		return res;
	}
	*state = params[0].value.a ? PAS_SECBOOT_ON : PAS_SECBOOT_OFF;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_get_root_anchor(uint8_t *anchor)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	params[0].memref.buffer = anchor;
	params[0].memref.size = PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE;
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_ROOT_OF_TRUST, pt, params);
	if (res)
		EMSG("PAS fuse: cannot read root of trust: %#"PRIx32, res);

	return res;
}

TEE_Result pas_fuse_get_hw_binding_info(struct pas_fuse_hw_binding_info *info)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			     TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_DEVICE_IDS, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read device ids: %#"PRIx32, res);
		return res;
	}
	info->ids.oem_id = params[0].value.a;
	info->ids.model_id = params[0].value.b;
	info->ids.jtag_id = params[1].value.a;
	info->ids.serial_num = params[1].value.b;

	memset(params, 0, sizeof(params));
	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_USE_SERIAL_NUM, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read USE_SERIAL_NUM fuse: %#"PRIx32,
		     res);
		return res;
	}
	info->use_serial_num_override = params[0].value.a;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_get_soc_hw_version(uint32_t *fam_dev)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_SOC_HW_VERSION, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read SOC_HW_VERSION: %#"PRIx32, res);
		return res;
	}

	*fam_dev = params[0].value.a;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_get_eku_enforcement_en(bool *eku_enforced)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_EKU_ENFORCEMENT_EN, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read EKU enforcement fuse: %#"PRIx32,
		     res);
		return res;
	}

	*eku_enforced = params[0].value.a;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_get_segment_hash_len(uint32_t root_cert_sel,
					 uint32_t *hash_len)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	params[0].value.a = root_cert_sel;
	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_SEGMENT_HASH_LEN, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read segment hash size: %#"PRIx32, res);
		return res;
	}

	*hash_len = params[0].value.b;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_get_mrc_info(struct pas_fuse_mrc_info *info)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	info->num_roots = 1;
	info->activation_list = 0;
	info->revocation_list = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			     TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_MRC_INFO, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read MRC info: %#"PRIx32, res);
		return res;
	}

	if (!params[0].value.a)
		return TEE_SUCCESS;

	info->num_roots = params[0].value.b;
	info->activation_list = params[1].value.a;
	info->revocation_list = params[1].value.b;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_get_pil_rollback_version(uint32_t *dev_ver)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_PIL_ROLLBACK_VERSION, pt,
			      params);
	if (res) {
		EMSG("PAS fuse: cannot read PIL rollback version: %#"PRIx32,
		     res);
		return res;
	}

	*dev_ver = params[0].value.a;

	return TEE_SUCCESS;
}

TEE_Result pas_fuse_blow_pil_rollback_version(uint32_t version)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	params[0].value.a = version;
	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_BLOW_PIL_ROLLBACK_VERSION, pt,
			      params);
	if (res)
		IMSG("PAS ARB: fuse advance failed: %#"PRIx32, res);

	return res;
}
