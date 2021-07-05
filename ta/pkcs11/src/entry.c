// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <pkcs11_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "object.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"

TEE_Result TA_CreateEntryPoint(void)
{
	return pkcs11_init();
}

void TA_DestroyEntryPoint(void)
{
	pkcs11_deinit();
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **tee_session)
{
	struct pkcs11_client *client = register_client();

	if (!client)
		return TEE_ERROR_OUT_OF_MEMORY;

	*tee_session = client;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *tee_session)
{
	struct pkcs11_client *client = tee_session2client(tee_session);

	unregister_client(client);
}

/*
 * Entry point for invocation command PKCS11_CMD_PING
 *
 * Return a PKCS11_CKR_* value which is also loaded into the output param#0
 */
static enum pkcs11_rc entry_ping(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *out = params + 2;
	const uint32_t ver[] = {
		PKCS11_TA_VERSION_MAJOR,
		PKCS11_TA_VERSION_MINOR,
		PKCS11_TA_VERSION_PATCH,
	};

	if (ptypes != exp_pt ||
	    params[0].memref.size != TEE_PARAM0_SIZE_MIN ||
	    out->memref.size != sizeof(ver))
		return PKCS11_CKR_ARGUMENTS_BAD;

	TEE_MemMove(out->memref.buffer, ver, sizeof(ver));

	return PKCS11_CKR_OK;
}

static bool __maybe_unused param_is_none(uint32_t ptypes, unsigned int index)
{
	return TEE_PARAM_TYPE_GET(ptypes, index) ==
	       TEE_PARAM_TYPE_NONE;
}

static bool __maybe_unused param_is_memref(uint32_t ptypes, unsigned int index)
{
	switch (TEE_PARAM_TYPE_GET(ptypes, index)) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

static bool __maybe_unused param_is_input(uint32_t ptypes, unsigned int index)
{
	return TEE_PARAM_TYPE_GET(ptypes, index) ==
	       TEE_PARAM_TYPE_MEMREF_INPUT;
}

static bool __maybe_unused param_is_output(uint32_t ptypes, unsigned int index)
{
	return TEE_PARAM_TYPE_GET(ptypes, index) ==
	       TEE_PARAM_TYPE_MEMREF_OUTPUT;
}

/*
 * Entry point for PKCS11 TA commands
 *
 * Param#0 (ctrl) is an output or an in/out buffer. Input data are serialized
 * arguments for the invoked command while the output data is used to send
 * back to the client a PKCS11 finer status ID than the GPD TEE result codes
 * Client shall check the status ID from the parameter #0 output buffer together
 * with the GPD TEE result code.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *tee_session, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	if (!client)
		return TEE_ERROR_SECURITY;

	/* All command handlers will check only against 4 parameters */
	COMPILE_TIME_ASSERT(TEE_NUM_PARAMS == 4);

	/*
	 * Param#0 must be either an output or an inout memref as used to
	 * store the output return value for the invoked command.
	 */
	switch (TEE_PARAM_TYPE_GET(ptypes, 0)) {
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		if (params[0].memref.size < sizeof(rc))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	DMSG("%s p#0 %"PRIu32"@%p, p#1 %s %"PRIu32"@%p, p#2 %s %"PRIu32"@%p",
	     id2str_ta_cmd(cmd),
	     params[0].memref.size, params[0].memref.buffer,
	     param_is_input(ptypes, 1) ? "in" :
	     param_is_output(ptypes, 1) ? "out" : "---",
	     param_is_memref(ptypes, 1) ? params[1].memref.size : 0,
	     param_is_memref(ptypes, 1) ? params[1].memref.buffer : NULL,
	     param_is_input(ptypes, 2) ? "in" :
	     param_is_output(ptypes, 2) ? "out" : "---",
	     param_is_memref(ptypes, 2) ? params[2].memref.size : 0,
	     param_is_memref(ptypes, 2) ? params[2].memref.buffer : NULL);

	switch (cmd) {
	case PKCS11_CMD_PING:
		rc = entry_ping(ptypes, params);
		break;

	case PKCS11_CMD_SLOT_LIST:
		rc = entry_ck_slot_list(ptypes, params);
		break;
	case PKCS11_CMD_SLOT_INFO:
		rc = entry_ck_slot_info(ptypes, params);
		break;
	case PKCS11_CMD_TOKEN_INFO:
		rc = entry_ck_token_info(ptypes, params);
		break;
	case PKCS11_CMD_MECHANISM_IDS:
		rc = entry_ck_token_mecha_ids(ptypes, params);
		break;
	case PKCS11_CMD_MECHANISM_INFO:
		rc = entry_ck_token_mecha_info(ptypes, params);
		break;

	case PKCS11_CMD_OPEN_SESSION:
		rc = entry_ck_open_session(client, ptypes, params);
		break;
	case PKCS11_CMD_CLOSE_SESSION:
		rc = entry_ck_close_session(client, ptypes, params);
		break;
	case PKCS11_CMD_CLOSE_ALL_SESSIONS:
		rc = entry_ck_close_all_sessions(client, ptypes, params);
		break;
	case PKCS11_CMD_SESSION_INFO:
		rc = entry_ck_session_info(client, ptypes, params);
		break;

	case PKCS11_CMD_INIT_TOKEN:
		rc = entry_ck_token_initialize(ptypes, params);
		break;
	case PKCS11_CMD_INIT_PIN:
		rc = entry_ck_init_pin(client, ptypes, params);
		break;
	case PKCS11_CMD_SET_PIN:
		rc = entry_ck_set_pin(client, ptypes, params);
		break;
	case PKCS11_CMD_LOGIN:
		rc = entry_ck_login(client, ptypes, params);
		break;
	case PKCS11_CMD_LOGOUT:
		rc = entry_ck_logout(client, ptypes, params);
		break;

	case PKCS11_CMD_CREATE_OBJECT:
		rc = entry_create_object(client, ptypes, params);
		break;
	case PKCS11_CMD_DESTROY_OBJECT:
		rc = entry_destroy_object(client, ptypes, params);
		break;

	case PKCS11_CMD_ENCRYPT_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT);
		break;
	case PKCS11_CMD_DECRYPT_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT);
		break;
	case PKCS11_CMD_ENCRYPT_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_DECRYPT_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_ENCRYPT_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_DECRYPT_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_ENCRYPT_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_ENCRYPT,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_DECRYPT_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DECRYPT,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_SIGN_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN);
		break;
	case PKCS11_CMD_VERIFY_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY);
		break;
	case PKCS11_CMD_SIGN_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_VERIFY_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_SIGN_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_VERIFY_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_SIGN_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_SIGN,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_VERIFY_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_VERIFY,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_GENERATE_KEY:
		rc = entry_generate_secret(client, ptypes, params);
		break;
	case PKCS11_CMD_FIND_OBJECTS_INIT:
		rc = entry_find_objects_init(client, ptypes, params);
		break;
	case PKCS11_CMD_FIND_OBJECTS:
		rc = entry_find_objects(client, ptypes, params);
		break;
	case PKCS11_CMD_FIND_OBJECTS_FINAL:
		rc = entry_find_objects_final(client, ptypes, params);
		break;
	case PKCS11_CMD_GET_ATTRIBUTE_VALUE:
		rc = entry_get_attribute_value(client, ptypes, params);
		break;
	case PKCS11_CMD_GET_OBJECT_SIZE:
		rc = entry_get_object_size(client, ptypes, params);
		break;
	case PKCS11_CMD_SET_ATTRIBUTE_VALUE:
		rc = entry_set_attribute_value(client, ptypes, params);
		break;
	case PKCS11_CMD_COPY_OBJECT:
		rc = entry_copy_object(client, ptypes, params);
		break;
	case PKCS11_CMD_SEED_RANDOM:
		rc = entry_ck_seed_random(client, ptypes, params);
		break;
	case PKCS11_CMD_GENERATE_RANDOM:
		rc = entry_ck_generate_random(client, ptypes, params);
		break;
	case PKCS11_CMD_DERIVE_KEY:
		rc = entry_processing_key(client, ptypes, params,
					  PKCS11_FUNCTION_DERIVE);
		break;
	case PKCS11_CMD_RELEASE_ACTIVE_PROCESSING:
		rc = entry_release_active_processing(client, ptypes, params);
		break;
	case PKCS11_CMD_DIGEST_INIT:
		rc = entry_processing_init(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST);
		break;
	case PKCS11_CMD_DIGEST_UPDATE:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_UPDATE);
		break;
	case PKCS11_CMD_DIGEST_KEY:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_UPDATE_KEY);
		break;
	case PKCS11_CMD_DIGEST_ONESHOT:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_ONESHOT);
		break;
	case PKCS11_CMD_DIGEST_FINAL:
		rc = entry_processing_step(client, ptypes, params,
					   PKCS11_FUNCTION_DIGEST,
					   PKCS11_FUNC_STEP_FINAL);
		break;
	case PKCS11_CMD_GENERATE_KEY_PAIR:
		rc = entry_generate_key_pair(client, ptypes, params);
		break;
	case PKCS11_CMD_WRAP_KEY:
		rc = entry_wrap_key(client, ptypes, params);
		break;
	case PKCS11_CMD_UNWRAP_KEY:
		rc = entry_processing_key(client, ptypes, params,
					  PKCS11_FUNCTION_UNWRAP);
		break;
	default:
		EMSG("Command %#"PRIx32" is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	DMSG("%s rc %#"PRIx32"/%s", id2str_ta_cmd(cmd), rc, id2str_rc(rc));

	TEE_MemMove(params[0].memref.buffer, &rc, sizeof(rc));
	params[0].memref.size = sizeof(rc);

	if (rc == PKCS11_CKR_BUFFER_TOO_SMALL)
		return TEE_ERROR_SHORT_BUFFER;
	else
		return TEE_SUCCESS;
}
