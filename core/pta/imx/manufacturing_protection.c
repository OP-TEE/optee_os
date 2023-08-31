// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019, 2023 NXP
 */
#include <drivers/caam_extension.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <pta_imx_manufacturing_protection.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>

#define PTA_NAME "manufacturing_protection.pta"

static TEE_Result mp_get_public_key(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *data = NULL;
	size_t size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	data = params[0].memref.buffer;
	size = params[0].memref.size;

	res = caam_mp_export_publickey(data, &size);
	if (res != TEE_SUCCESS)
		EMSG("MP public key export failed with code 0x%" PRIx32, res);

	params[0].memref.size = size;
	return res;
}

static TEE_Result mp_signature(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *msg = NULL;
	uint8_t *sig = NULL;
	uint8_t *mpmr = NULL;
	size_t msg_size = 0;
	size_t sig_size = 0;
	size_t mpmr_size = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("MPSign function");

	msg = params[0].memref.buffer;
	msg_size = params[0].memref.size;
	sig = params[1].memref.buffer;
	sig_size = params[1].memref.size;
	mpmr = params[2].memref.buffer;
	mpmr_size = params[2].memref.size;

	memset(sig, 0, sig_size);
	memset(mpmr, 0, mpmr_size);

	res = caam_mp_sign(msg, &msg_size, sig, &sig_size);

	params[1].memref.size = sig_size;

	if (res != TEE_SUCCESS) {
		EMSG("Manufacturing Protection signature failed 0x%" PRIx32,
		     res);
		return res;
	}

	res = caam_mp_export_mpmr(mpmr, &mpmr_size);

	params[2].memref.size = mpmr_size;

	if (res != TEE_SUCCESS)
		EMSG("Manufacturing Protection export MPRM failed 0x%" PRIx32,
		     res);

	return res;
}

static TEE_Result
pta_mp_open_session(uint32_t param_types __unused,
		    TEE_Param params[TEE_NUM_PARAMS] __unused,
		    void **sess_ctx __unused)
{
	struct ts_session *s = NULL;

	if (IS_ENABLED(CFG_NXP_CAAM_MP_NO_ACCESS_CTRL))
		return TEE_SUCCESS;

	s = ts_get_calling_session();
	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result pta_mp_invoke_cmd(void *sess_ctx __unused,
				    uint32_t cmd_id, uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_IMX_MP_CMD_SIGNATURE_MPMR:
		return mp_signature(param_types, params);
	case PTA_IMX_MP_CMD_GET_PUBLIC_KEY:
		return mp_get_public_key(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_MANUFACT_PROTEC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = pta_mp_open_session,
		   .invoke_command_entry_point = pta_mp_invoke_cmd);
