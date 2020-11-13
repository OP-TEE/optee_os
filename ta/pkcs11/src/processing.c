// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

static enum pkcs11_rc get_ready_session(struct pkcs11_session *session)
{
	if (session_is_active(session))
		return PKCS11_CKR_OPERATION_ACTIVE;

	return PKCS11_CKR_OK;
}

static bool func_matches_state(enum processing_func function,
			       enum pkcs11_proc_state state)
{
	switch (function) {
	case PKCS11_FUNCTION_ENCRYPT:
		return state == PKCS11_SESSION_ENCRYPTING ||
		       state == PKCS11_SESSION_DIGESTING_ENCRYPTING ||
		       state == PKCS11_SESSION_SIGNING_ENCRYPTING;
	case PKCS11_FUNCTION_DECRYPT:
		return state == PKCS11_SESSION_DECRYPTING ||
		       state == PKCS11_SESSION_DECRYPTING_DIGESTING ||
		       state == PKCS11_SESSION_DECRYPTING_VERIFYING;
	case PKCS11_FUNCTION_DIGEST:
		return state == PKCS11_SESSION_DIGESTING ||
		       state == PKCS11_SESSION_DIGESTING_ENCRYPTING;
	case PKCS11_FUNCTION_SIGN:
		return state == PKCS11_SESSION_SIGNING ||
		       state == PKCS11_SESSION_SIGNING_ENCRYPTING;
	case PKCS11_FUNCTION_VERIFY:
		return state == PKCS11_SESSION_VERIFYING ||
		       state == PKCS11_SESSION_DECRYPTING_VERIFYING;
	case PKCS11_FUNCTION_SIGN_RECOVER:
		return state == PKCS11_SESSION_SIGNING_RECOVER;
	case PKCS11_FUNCTION_VERIFY_RECOVER:
		return state == PKCS11_SESSION_SIGNING_RECOVER;
	default:
		TEE_Panic(function);
		return false;
	}
}

static enum pkcs11_rc get_active_session(struct pkcs11_session *session,
					 enum processing_func function)
{
	enum pkcs11_rc rc = PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	if (session->processing &&
	    func_matches_state(function, session->processing->state))
		rc = PKCS11_CKR_OK;

	return rc;
}

void release_active_processing(struct pkcs11_session *session)
{
	if (!session->processing)
		return;

	switch (session->processing->mecha_type) {
	case PKCS11_CKM_AES_CTR:
		tee_release_ctr_operation(session->processing);
		break;
	default:
		break;
	}

	if (session->processing->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session->processing->tee_op_handle);
		session->processing->tee_op_handle = TEE_HANDLE_NULL;
	}

	TEE_Free(session->processing);
	session->processing = NULL;
}

size_t get_object_key_bit_size(struct pkcs11_object *obj)
{
	uint32_t a_size = 0;
	struct obj_attrs *attrs = obj->attributes;

	switch (get_key_type(attrs)) {
	case PKCS11_CKK_AES:
		if (get_attribute_ptr(attrs, PKCS11_CKA_VALUE, NULL, &a_size))
			return 0;

		return a_size * 8;
	default:
		TEE_Panic(0);
		return 0;
	}
}

/*
 * entry_processing_init - Generic entry for initializing a processing
 *
 * @client = client reference
 * @ptype = Invocation parameter types
 * @params = Invocation parameters reference
 * @function - encrypt, decrypt, sign, verify, digest, ...
 */
enum pkcs11_rc entry_processing_init(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	uint32_t key_handle = 0;
	struct pkcs11_object *obj = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &key_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	rc = get_ready_session(session);
	if (rc)
		goto out;

	obj = pkcs11_handle2object(key_handle, session);
	if (!obj) {
		rc = PKCS11_CKR_KEY_HANDLE_INVALID;
		goto out;
	}

	rc = set_processing_state(session, function, obj, NULL);
	if (rc)
		goto out;

	rc = check_mechanism_against_processing(session, proc_params->id,
						function,
						PKCS11_FUNC_STEP_INIT);
	if (rc)
		goto out;

	rc = check_parent_attrs_against_processing(proc_params->id, function,
						   obj->attributes);
	if (rc)
		goto out;

	rc = check_access_attrs_against_token(session, obj->attributes);
	if (rc)
		goto out;

	if (processing_is_tee_symm(proc_params->id))
		rc = init_symm_operation(session, function, proc_params, obj);
	else
		rc = PKCS11_CKR_MECHANISM_INVALID;

	if (rc == PKCS11_CKR_OK) {
		session->processing->mecha_type = proc_params->id;
		DMSG("PKCS11 session %"PRIu32": init processing %s %s",
		     session->handle, id2str_proc(proc_params->id),
		     id2str_function(function));
	}

out:
	if (rc && session)
		release_active_processing(session);

	TEE_Free(proc_params);

	return rc;
}

/*
 * entry_processing_step - Generic entry on active processing
 *
 * @client = client reference
 * @ptype = Invocation parameter types
 * @params = Invocation parameters reference
 * @function - encrypt, decrypt, sign, verify, digest, ...
 * @step - update, oneshot, final
 */
enum pkcs11_rc entry_processing_step(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function,
				     enum processing_step step)
{
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	enum pkcs11_mechanism_id mecha_type = PKCS11_CKM_UNDEFINED_ID;

	if (!client ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	rc = get_active_session(session, function);
	if (rc)
		return rc;

	mecha_type = session->processing->mecha_type;
	rc = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rc)
		goto out;

	if (processing_is_tee_symm(mecha_type))
		rc = step_symm_operation(session, function, step,
					 ptypes, params);
	else
		rc = PKCS11_CKR_MECHANISM_INVALID;

	if (rc == PKCS11_CKR_OK) {
		session->processing->updated = true;
		DMSG("PKCS11 session%"PRIu32": processing %s %s",
		     session->handle, id2str_proc(mecha_type),
		     id2str_function(function));
	}

out:
	switch (step) {
	case PKCS11_FUNC_STEP_UPDATE:
		if (rc != PKCS11_CKR_OK && rc != PKCS11_CKR_BUFFER_TOO_SMALL)
			release_active_processing(session);
		break;
	default:
		/* ONESHOT and FINAL terminates processing on success */
		if (rc != PKCS11_CKR_BUFFER_TOO_SMALL)
			release_active_processing(session);
		break;
	}

	return rc;
}

/*
 * entry_verify_oneshot - Run a single part verification processing
 *
 * @client = client reference
 * @ptype = Invocation parameter types
 * @params = Invocation parameters reference
 * @function - encrypt, decrypt, sign, verify, digest, ...
 * @step - update, oneshot, final
 */
enum pkcs11_rc entry_verify_oneshot(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params,
				    enum processing_func function,
				    enum processing_step step)

{
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	enum pkcs11_mechanism_id mecha_type = PKCS11_CKM_UNDEFINED_ID;

	assert(function == PKCS11_FUNCTION_VERIFY);
	if (!client ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	rc = get_active_session(session, function);
	if (rc)
		return rc;

	mecha_type = session->processing->mecha_type;
	rc = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rc)
		goto out;

	if (processing_is_tee_symm(mecha_type))
		rc = step_symm_operation(session, function, step,
					 ptypes, params);
	else
		rc = PKCS11_CKR_MECHANISM_INVALID;

	DMSG("PKCS11 session %"PRIu32": verify %s %s: %s", session->handle,
	     id2str_proc(mecha_type), id2str_function(function),
	     id2str_rc(rc));

out:
	if (rc != PKCS11_CKR_BUFFER_TOO_SMALL)
		release_active_processing(session);

	return rc;
}
