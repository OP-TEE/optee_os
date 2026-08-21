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

	res = TEE_OpenTASession(&fuse_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&fuse_session, NULL);
	if (res)
		EMSG("PAS fuse: cannot open fuse PTA: %#"PRIx32, res);

	return res;
}

void pas_fuse_close(void)
{
	TEE_CloseTASession(fuse_session);
}

static TEE_Result fuse_pta_invoke(uint32_t cmd, uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	return TEE_InvokeTACommand(fuse_session, TEE_TIMEOUT_INFINITE, cmd,
				   param_types, params, NULL);
}

TEE_Result pas_fuse_get_secboot_and_root_anchor(uint8_t *anchor,
						bool *secboot_on)
{
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pt = 0;

	*secboot_on = false;

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_SECBOOT_STATE, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read secboot state: %#"PRIx32, res);
		return res;
	}
	*secboot_on = params[0].value.a != 0;

	memset(params, 0, sizeof(params));
	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	params[0].memref.buffer = anchor;
	params[0].memref.size = PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE;
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_ROOT_OF_TRUST, pt, params);
	if (res)
		EMSG("PAS fuse: cannot read root of trust: %#"PRIx32, res);

	return res;
}

TEE_Result pas_fuse_get_hw_binding_info(bool need_soc_vers,
					struct pas_fuse_hw_binding_info *info)
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

	if (!need_soc_vers)
		return TEE_SUCCESS;

	memset(params, 0, sizeof(params));
	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = fuse_pta_invoke(PTA_QCOM_FUSE_GET_SOC_HW_VERSION, pt, params);
	if (res) {
		EMSG("PAS fuse: cannot read SOC_HW_VERSION: %#"PRIx32, res);
		return res;
	}
	info->soc_fam_dev = params[0].value.a;

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
