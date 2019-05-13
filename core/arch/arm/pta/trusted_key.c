// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <pta_trusted_key.h>
#include <string.h>
#include <tee/tee_fs_key_manager.h>
#include <tee/uuid.h>
#include <user_ta_header.h>

#define PTA_NAME "trusted_key.pta"

static TEE_Result get_random(uint32_t types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("Invoked TA_CMD_GET_RANDOM");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	return crypto_rng_read(params[0].memref.buffer, params[0].memref.size);
}

static TEE_Result seal_trusted_key(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	const TEE_UUID uuid = PTA_TRUSTED_KEY_UUID;

	FMSG("Invoked TA_CMD_SEAL");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[1].memref.buffer || params[1].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_fs_fek_crypt(&uuid, TEE_MODE_ENCRYPT, params[0].memref.buffer,
			       params[0].memref.size, params[1].memref.buffer);
	if (res == TEE_SUCCESS)
		params[1].memref.size = params[0].memref.size;
	else
		params[1].memref.size = 0;

	return res;
}

static TEE_Result unseal_trusted_key(uint32_t types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	const TEE_UUID uuid = PTA_TRUSTED_KEY_UUID;

	FMSG("Invoked TA_CMD_UNSEAL");

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[1].memref.buffer || params[1].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_fs_fek_crypt(&uuid, TEE_MODE_DECRYPT, params[0].memref.buffer,
			       params[0].memref.size, params[1].memref.buffer);
	if (res == TEE_SUCCESS)
		params[1].memref.size = params[0].memref.size;
	else
		params[1].memref.size = 0;

	return res;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	switch (nCommandID) {
	case TA_CMD_GET_RANDOM:
		return get_random(nParamTypes, pParams);
	case TA_CMD_SEAL:
		return seal_trusted_key(nParamTypes, pParams);
	case TA_CMD_UNSEAL:
		return unseal_trusted_key(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_ta_session *s;

	/* Check that we're called from a REE kernel client */
	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;
	if (s->clnt_id.login != TEE_LOGIN_REE_KERNEL)
		res = TEE_ERROR_ACCESS_DENIED;

	return res;
}


pseudo_ta_register(.uuid = PTA_TRUSTED_KEY_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
