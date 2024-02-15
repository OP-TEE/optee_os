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

static enum processing_func func_for_cmd(enum pkcs11_ta_cmd cmd)
{
	switch (cmd) {
	case PKCS11_CMD_ENCRYPT_UPDATE:
	case PKCS11_CMD_ENCRYPT_ONESHOT:
	case PKCS11_CMD_ENCRYPT_FINAL:
		return PKCS11_FUNCTION_ENCRYPT;
	case PKCS11_CMD_DECRYPT_UPDATE:
	case PKCS11_CMD_DECRYPT_ONESHOT:
	case PKCS11_CMD_DECRYPT_FINAL:
		return PKCS11_FUNCTION_DECRYPT;
	case PKCS11_CMD_SIGN_ONESHOT:
	case PKCS11_CMD_SIGN_UPDATE:
	case PKCS11_CMD_SIGN_FINAL:
		return PKCS11_FUNCTION_SIGN;
	case PKCS11_CMD_VERIFY_ONESHOT:
	case PKCS11_CMD_VERIFY_UPDATE:
	case PKCS11_CMD_VERIFY_FINAL:
		return PKCS11_FUNCTION_VERIFY;
	case PKCS11_CMD_DIGEST_UPDATE:
	case PKCS11_CMD_DIGEST_KEY:
	case PKCS11_CMD_DIGEST_ONESHOT:
	case PKCS11_CMD_DIGEST_FINAL:
		return PKCS11_FUNCTION_DIGEST;
	default:
		return PKCS11_FUNCTION_UNKNOWN;
	}
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
	case PKCS11_CKM_AES_GCM:
		tee_release_gcm_operation(session);
		break;
	default:
		break;
	}

	if (session->processing->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session->processing->tee_op_handle);
		session->processing->tee_op_handle = TEE_HANDLE_NULL;
	}

	if (session->processing->tee_op_handle2 != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session->processing->tee_op_handle2);
		session->processing->tee_op_handle2 = TEE_HANDLE_NULL;
	}

	TEE_Free(session->processing->extra_ctx);

	TEE_Free(session->processing);
	session->processing = NULL;
}

size_t get_object_key_bit_size(struct pkcs11_object *obj)
{
	void *a_ptr = NULL;
	uint32_t a_size = 0;
	struct obj_attrs *attrs = obj->attributes;

	switch (get_key_type(attrs)) {
	case PKCS11_CKK_AES:
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
		if (get_attribute_ptr(attrs, PKCS11_CKA_VALUE, NULL, &a_size))
			return 0;

		return a_size * 8;
	case PKCS11_CKK_RSA:
		if (get_attribute_ptr(attrs, PKCS11_CKA_MODULUS, NULL, &a_size))
			return 0;

		return a_size * 8;
	case PKCS11_CKK_EC:
		if (get_attribute_ptr(attrs, PKCS11_CKA_EC_PARAMS,
				      &a_ptr, &a_size) || !a_ptr)
			return 0;

		return ec_params2tee_keysize(a_ptr, a_size);
	case PKCS11_CKK_EC_EDWARDS:
		if (get_attribute_ptr(attrs, PKCS11_CKA_EC_POINT, NULL,
				      &a_size))
			return 0;

		return a_size * 8;
	default:
		TEE_Panic(0);
		return 0;
	}
}

static enum pkcs11_rc generate_random_key_value(struct obj_attrs **head)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t data_size = 0;
	uint32_t value_len = 0;
	void *value = NULL;
	void *data = NULL;

	if (!*head)
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;

	rc = get_attribute_ptr(*head, PKCS11_CKA_VALUE_LEN, &data, &data_size);
	if (rc || data_size != sizeof(uint32_t)) {
		DMSG("%s", rc ? "No attribute value_len found" :
		     "Invalid size for attribute VALUE_LEN");

		return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
	}
	TEE_MemMove(&value_len, data, data_size);

	/* Remove the default empty value attribute if found */
	rc = remove_empty_attribute(head, PKCS11_CKA_VALUE);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		return PKCS11_CKR_GENERAL_ERROR;

	value = TEE_Malloc(value_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!value)
		return PKCS11_CKR_DEVICE_MEMORY;

	TEE_GenerateRandom(value, value_len);

	rc = add_attribute(head, PKCS11_CKA_VALUE, value, value_len);

	if (rc == PKCS11_CKR_OK)
		rc = set_check_value_attr(head);

	TEE_Free(value);

	return rc;
}

enum pkcs11_rc entry_generate_secret(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	struct obj_attrs *head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t obj_handle = 0;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rc)
		goto out;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		goto out;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	rc = get_ready_session(session);
	if (rc)
		goto out;

	template_size = sizeof(*template) + template->attrs_size;

	rc = check_mechanism_against_processing(session, proc_params->id,
						PKCS11_FUNCTION_GENERATE,
						PKCS11_FUNC_STEP_INIT);
	if (rc) {
		DMSG("Invalid mechanism %#"PRIx32": %#x", proc_params->id, rc);
		goto out;
	}

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temporary template once done.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     NULL, PKCS11_FUNCTION_GENERATE,
					     proc_params->id,
					     PKCS11_CKO_UNDEFINED_ID);
	if (rc)
		goto out;

	TEE_Free(template);
	template = NULL;

	rc = check_created_attrs(head, NULL);
	if (rc)
		goto out;

	rc = check_created_attrs_against_processing(proc_params->id, head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_token(session, head);
	if (rc)
		goto out;

	/*
	 * Execute target processing and add value as attribute
	 * PKCS11_CKA_VALUE. Symm key generation: depends on target
	 * processing to be used.
	 */
	switch (proc_params->id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
	case PKCS11_CKM_AES_KEY_GEN:
		/* Generate random of size specified by attribute VALUE_LEN */
		rc = generate_random_key_value(&head);
		if (rc)
			goto out;
		break;

	default:
		rc = PKCS11_CKR_MECHANISM_INVALID;
		goto out;
	}

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rc = create_object(session, head, &obj_handle);
	if (rc)
		goto out;

	/*
	 * Now obj_handle (through the related struct pkcs11_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset head to NULL as it is no more the buffer owner and would
	 * be freed at function out.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": generate secret %#"PRIx32,
	     session->handle, obj_handle);

out:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(head);

	return rc;
}

enum pkcs11_rc alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					    uint32_t attribute,
					    void **data, size_t *size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *ptr = NULL;
	size_t sz = 0;

	res = TEE_GetObjectBufferAttribute(tee_obj, attribute, NULL, &sz);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return PKCS11_CKR_FUNCTION_FAILED;

	ptr = TEE_Malloc(sz, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!ptr)
		return PKCS11_CKR_DEVICE_MEMORY;

	res = TEE_GetObjectBufferAttribute(tee_obj, attribute, ptr, &sz);
	if (res) {
		TEE_Free(ptr);
	} else {
		*data = ptr;
		*size = sz;
	}

	return tee2pkcs_error(res);
}

enum pkcs11_rc tee2pkcs_add_attribute(struct obj_attrs **head,
				      uint32_t pkcs11_id,
				      TEE_ObjectHandle tee_obj,
				      uint32_t tee_id)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;
	size_t a_size = 0;

	rc = alloc_get_tee_attribute_data(tee_obj, tee_id, &a_ptr, &a_size);
	if (rc)
		goto out;

	rc = add_attribute(head, pkcs11_id, a_ptr, a_size);

	TEE_Free(a_ptr);

out:
	if (rc)
		EMSG("Failed TEE attribute %#"PRIx32" for %#"PRIx32"/%s",
		     tee_id, pkcs11_id, id2str_attr(pkcs11_id));
	return rc;
}

enum pkcs11_rc entry_generate_key_pair(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	struct obj_attrs *pub_head = NULL;
	struct obj_attrs *priv_head = NULL;
	struct pkcs11_object_head *pub_template = NULL;
	struct pkcs11_object_head *priv_template = NULL;
	struct pkcs11_object *object = NULL;
	size_t pub_template_size = 0;
	size_t priv_template_size = 0;
	uint32_t pubkey_handle = 0;
	uint32_t privkey_handle = 0;
	uint32_t *hdl_ptr = NULL;
	size_t out_ref_size = sizeof(pubkey_handle) + sizeof(privkey_handle);

	if (!client || ptypes != exp_pt || out->memref.size != out_ref_size)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rc)
		goto out;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &pub_template);
	if (rc)
		goto out;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &priv_template);
	if (rc)
		goto out;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out;
	}

	rc = get_ready_session(session);
	if (rc)
		goto out;

	rc = check_mechanism_against_processing(session, proc_params->id,
						PKCS11_FUNCTION_GENERATE_PAIR,
						PKCS11_FUNC_STEP_INIT);
	if (rc)
		goto out;

	pub_template_size = sizeof(*pub_template) + pub_template->attrs_size;

	rc = create_attributes_from_template(&pub_head, pub_template,
					     pub_template_size, NULL,
					     PKCS11_FUNCTION_GENERATE_PAIR,
					     proc_params->id,
					     PKCS11_CKO_PUBLIC_KEY);
	if (rc)
		goto out;

	TEE_Free(pub_template);
	pub_template = NULL;

	priv_template_size = sizeof(*priv_template) +
			     priv_template->attrs_size;

	rc = create_attributes_from_template(&priv_head, priv_template,
					     priv_template_size, NULL,
					     PKCS11_FUNCTION_GENERATE_PAIR,
					     proc_params->id,
					     PKCS11_CKO_PRIVATE_KEY);
	if (rc)
		goto out;

	TEE_Free(priv_template);
	priv_template = NULL;

	/* Generate CKA_ID for keys if not specified by the templates */
	rc = add_missing_attribute_id(&pub_head, &priv_head);
	if (rc)
		goto out;

	/* Check created object against processing and token state */
	rc = check_created_attrs(pub_head, priv_head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_processing(proc_params->id, pub_head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_processing(proc_params->id,
						    priv_head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_token(session, pub_head);
	if (rc)
		goto out;

	rc = check_access_attrs_against_token(session, pub_head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_token(session, priv_head);
	if (rc)
		goto out;

	rc = check_access_attrs_against_token(session, priv_head);
	if (rc)
		goto out;

	/* Generate key pair */
	switch (proc_params->id) {
	case PKCS11_CKM_EC_EDWARDS_KEY_PAIR_GEN:
		rc = generate_eddsa_keys(proc_params, &pub_head, &priv_head);
		break;
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
		rc = generate_ec_keys(proc_params, &pub_head, &priv_head);
		break;
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		rc = generate_rsa_keys(proc_params, &pub_head, &priv_head);
		break;
	default:
		rc = PKCS11_CKR_MECHANISM_INVALID;
		break;
	}
	if (rc)
		goto out;

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rc = create_object(session, pub_head, &pubkey_handle);
	if (rc)
		goto out;

	/*
	 * Now obj_handle (through the related struct pkcs11_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset local pub_head to NULL to mark that ownership has been
	 * transferred.
	 */
	pub_head = NULL;

	rc = create_object(session, priv_head, &privkey_handle);
	if (rc)
		goto out;

	/* Ownership has been transferred so mark it with NULL */
	priv_head = NULL;

	hdl_ptr = (uint32_t *)out->memref.buffer;

	TEE_MemMove(hdl_ptr, &pubkey_handle, sizeof(pubkey_handle));
	TEE_MemMove(hdl_ptr + 1, &privkey_handle, sizeof(privkey_handle));

	DMSG("PKCS11 session %"PRIu32": create key pair %#"PRIx32"/%#"PRIx32,
	     session->handle, privkey_handle, pubkey_handle);

	pubkey_handle = 0;
	privkey_handle = 0;
out:
	if (pubkey_handle) {
		object = pkcs11_handle2object(pubkey_handle, session);
		if (!object)
			TEE_Panic(0);
		destroy_object(session, object, false);
	}
	TEE_Free(priv_head);
	TEE_Free(pub_head);
	TEE_Free(priv_template);
	TEE_Free(pub_template);
	TEE_Free(proc_params);

	return rc;
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

	if (function != PKCS11_FUNCTION_DIGEST) {
		rc = serialargs_get(&ctrlargs, &key_handle, sizeof(uint32_t));
		if (rc)
			return rc;
	}

	rc = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out_free;
	}

	rc = get_ready_session(session);
	if (rc)
		goto out_free;

	if (function != PKCS11_FUNCTION_DIGEST) {
		obj = pkcs11_handle2object(key_handle, session);
		if (!obj) {
			rc = PKCS11_CKR_KEY_HANDLE_INVALID;
			goto out_free;
		}
	}

	rc = set_processing_state(session, function, obj, NULL);
	if (rc)
		goto out;

	rc = check_mechanism_against_processing(session, proc_params->id,
						function,
						PKCS11_FUNC_STEP_INIT);
	if (rc)
		goto out;

	if (obj) {
		rc = check_parent_attrs_against_processing(proc_params->id,
							   function,
							   obj->attributes);
		if (rc)
			goto out;

		rc = check_access_attrs_against_token(session,
						      obj->attributes);
		if (rc)
			goto out;
	}

	if (processing_is_tee_symm(proc_params->id))
		rc = init_symm_operation(session, function, proc_params, obj);
	else if (processing_is_tee_asymm(proc_params->id))
		rc = init_asymm_operation(session, function, proc_params, obj);
	else if (processing_is_tee_digest(proc_params->id))
		rc = init_digest_operation(session, proc_params);
	else
		rc = PKCS11_CKR_MECHANISM_INVALID;

	if (rc == PKCS11_CKR_OK) {
		DMSG("PKCS11 session %"PRIu32": init processing %s %s",
		     session->handle, id2str_proc(proc_params->id),
		     id2str_function(function));
	}

out:
	if (rc)
		release_active_processing(session);
out_free:
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
	uint32_t key_handle = 0;
	struct pkcs11_object *obj = NULL;

	if (!client ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (step == PKCS11_FUNC_STEP_UPDATE_KEY) {
		assert(function == PKCS11_FUNCTION_DIGEST);

		rc = serialargs_get(&ctrlargs, &key_handle, sizeof(uint32_t));
		if (rc)
			return rc;
	}

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	rc = get_active_session(session, function);
	if (rc)
		return rc;

	if (step == PKCS11_FUNC_STEP_UPDATE_KEY) {
		assert(function == PKCS11_FUNCTION_DIGEST);

		obj = pkcs11_handle2object(key_handle, session);
		if (!obj) {
			rc = PKCS11_CKR_KEY_HANDLE_INVALID;
			goto out;
		}

		rc = check_access_attrs_against_token(session,
						      obj->attributes);
		if (rc) {
			rc = PKCS11_CKR_KEY_HANDLE_INVALID;
			goto out;
		}
	}

	mecha_type = session->processing->mecha_type;
	rc = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rc)
		goto out;

	if (processing_is_tee_symm(mecha_type))
		rc = step_symm_operation(session, function, step,
					 ptypes, params);
	else if (processing_is_tee_asymm(mecha_type))
		rc = step_asymm_operation(session, function, step,
					  ptypes, params);
	else if (processing_is_tee_digest(mecha_type))
		rc = step_digest_operation(session, step, obj, ptypes, params);
	else
		rc = PKCS11_CKR_MECHANISM_INVALID;

	if (rc == PKCS11_CKR_OK && (step == PKCS11_FUNC_STEP_UPDATE ||
				    step == PKCS11_FUNC_STEP_UPDATE_KEY)) {
		session->processing->step = PKCS11_FUNC_STEP_UPDATE;
		DMSG("PKCS11 session%"PRIu32": processing %s %s",
		     session->handle, id2str_proc(mecha_type),
		     id2str_function(function));
	}

	if (rc == PKCS11_CKR_BUFFER_TOO_SMALL &&
	    step == PKCS11_FUNC_STEP_ONESHOT)
		session->processing->step = PKCS11_FUNC_STEP_ONESHOT;

	if (rc == PKCS11_CKR_BUFFER_TOO_SMALL && step == PKCS11_FUNC_STEP_FINAL)
		session->processing->step = PKCS11_FUNC_STEP_FINAL;

out:
	switch (step) {
	case PKCS11_FUNC_STEP_UPDATE:
	case PKCS11_FUNC_STEP_UPDATE_KEY:
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

enum pkcs11_rc entry_processing_key(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params,
				    enum processing_func function)
{
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	struct pkcs11_object_head *template = NULL;
	uint32_t parent_handle = 0;
	uint32_t obj_handle = 0;
	struct pkcs11_object *parent = NULL;
	struct obj_attrs *head = NULL;
	size_t template_size = 0;
	void *in_buf = NULL;
	uint32_t in_size = 0;
	void *out_buf = NULL;
	uint32_t out_size = 0;
	enum processing_func operation = PKCS11_FUNCTION_UNKNOWN;

	if (!client ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT ||
	    TEE_PARAM_TYPE_GET(ptypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    out->memref.size != sizeof(obj_handle) ||
	    TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (function) {
	case PKCS11_FUNCTION_UNWRAP:
		if (TEE_PARAM_TYPE_GET(ptypes, 1) !=
				TEE_PARAM_TYPE_MEMREF_INPUT)
			return PKCS11_CKR_ARGUMENTS_BAD;

		in_buf = params[1].memref.buffer;
		in_size = params[1].memref.size;
		if (in_size && !in_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;

		/*
		 * Some unwrap mechanisms require encryption to be
		 * performed on the data passed in proc_params by parent
		 * key. Hence set operation as PKCS11_FUNCTION_DECRYPT
		 * to be used with init_symm_operation()
		 */
		operation = PKCS11_FUNCTION_DECRYPT;
		break;
	case PKCS11_FUNCTION_DERIVE:
		if (TEE_PARAM_TYPE_GET(ptypes, 1) != TEE_PARAM_TYPE_NONE)
			return PKCS11_CKR_ARGUMENTS_BAD;

		/*
		 * Some derivation mechanism require encryption to be
		 * performed on the data passed in proc_params by parent
		 * key. Hence set operation as PKCS11_FUNCTION_ENCRYPT
		 * to be used with init_symm_operation()
		 */
		operation = PKCS11_FUNCTION_ENCRYPT;
		break;
	default:
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &parent_handle, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rc)
		return rc;

	rc = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rc)
		goto out_free;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rc = PKCS11_CKR_ARGUMENTS_BAD;
		goto out_free;
	}

	/* Return error if processing already active */
	rc = get_ready_session(session);
	if (rc)
		goto out_free;

	/* Check parent handle */
	parent = pkcs11_handle2object(parent_handle, session);
	if (!parent) {
		rc = PKCS11_CKR_KEY_HANDLE_INVALID;
		goto out_free;
	}

	/* Check if mechanism can be used for derivation function */
	rc = check_mechanism_against_processing(session, proc_params->id,
						function,
						PKCS11_FUNC_STEP_INIT);
	if (rc)
		goto out_free;

	/* Set the processing state to active */
	rc = set_processing_state(session, function, parent, NULL);
	if (rc)
		goto out_free;

	/*
	 * Check if base/parent key has CKA_DERIVE set and its key type is
	 * compatible with the mechanism passed
	 */
	rc = check_parent_attrs_against_processing(proc_params->id, function,
						   parent->attributes);
	if (rc) {
		/*
		 * CKR_KEY_FUNCTION_NOT_PERMITTED is not in the list of errors
		 * specified with C_Derive/Unwrap() in the specification. So
		 * return the next most appropriate error.
		 */
		if (rc == PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED) {
			if (function == PKCS11_FUNCTION_UNWRAP)
				rc =
				  PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
			else
				rc = PKCS11_CKR_KEY_TYPE_INCONSISTENT;
		}
		goto out;
	}

	/* Check access of base/parent key */
	rc = check_access_attrs_against_token(session, parent->attributes);
	if (rc)
		goto out;

	template_size = sizeof(*template) + template->attrs_size;
	/*
	 * Prepare a clean initial state for the requested object attributes
	 * using base/parent key attributes. Free temporary template once done.
	 */
	rc = create_attributes_from_template(&head, template, template_size,
					     parent->attributes,
					     function,
					     proc_params->id,
					     PKCS11_CKO_UNDEFINED_ID);
	if (rc)
		goto out;

	TEE_Free(template);
	template = NULL;

	/* check_created_attrs() is called later once key size is known */

	rc = check_created_attrs_against_processing(proc_params->id, head);
	if (rc)
		goto out;

	rc = check_created_attrs_against_token(session, head);
	if (rc)
		goto out;

	rc = check_access_attrs_against_token(session, head);
	if (rc)
		goto out;

	if (processing_is_tee_symm(proc_params->id)) {
		rc = init_symm_operation(session, operation, proc_params,
					 parent);
		if (rc)
			goto out;

		switch (function) {
		case PKCS11_FUNCTION_DERIVE:
			rc = derive_key_by_symm_enc(session, &out_buf,
						    &out_size);
			break;
		case PKCS11_FUNCTION_UNWRAP:
			rc = unwrap_key_by_symm(session, in_buf, in_size,
						&out_buf, &out_size);
			break;
		default:
			TEE_Panic(function);
		}
		if (rc)
			goto out;

	} else if (processing_is_tee_asymm(proc_params->id)) {
		switch (function) {
		case PKCS11_FUNCTION_DERIVE:
			rc = init_asymm_operation(session, function,
						  proc_params, parent);
			if (rc)
				goto out;

			rc = do_asymm_derivation(session, proc_params, &head);
			if (!rc)
				goto done;
			break;
		case PKCS11_FUNCTION_UNWRAP:
			rc = init_asymm_operation(session, operation,
						  proc_params, parent);
			if (rc)
				goto out;

			rc = unwrap_key_by_asymm(session, in_buf, in_size,
						 &out_buf, &out_size);
			break;
		default:
			TEE_Panic(function);
		}

		if (rc)
			goto out;
	} else {
		rc = PKCS11_CKR_MECHANISM_INVALID;
		goto out;
	}

	rc = set_key_data(&head, out_buf, out_size);
	if (rc)
		goto out;

done:
	TEE_Free(out_buf);
	out_buf = NULL;

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rc = create_object(session, head, &obj_handle);
	if (rc)
		goto out;

	/*
	 * Now obj_handle (through the related struct pkcs11_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset head to NULL as it is no more the buffer owner and would
	 * be freed at function out.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": derive secret %#"PRIx32,
	     session->handle, obj_handle);

out:
	release_active_processing(session);
out_free:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(head);
	TEE_Free(out_buf);

	return rc;
}

enum pkcs11_rc entry_release_active_processing(struct pkcs11_client *client,
					       uint32_t ptypes,
					       TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	enum processing_func function = PKCS11_FUNCTION_UNKNOWN;
	uint32_t cmd = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get_u32(&ctrlargs, &cmd);

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	function = func_for_cmd(cmd);
	if (function == PKCS11_FUNCTION_UNKNOWN)
		return PKCS11_CKR_ARGUMENTS_BAD;

	rc = get_active_session(session, function);
	if (rc)
		return rc;

	release_active_processing(session);

	DMSG("PKCS11 session %"PRIu32": release processing", session->handle);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_wrap_key(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	struct pkcs11_object *wrapping_key = NULL;
	struct pkcs11_object *key = NULL;
	void *req_attrs = NULL;
	uint32_t wrapping_key_handle = 0;
	uint32_t key_handle = 0;
	uint32_t size = 0;
	void *key_data = NULL;
	uint32_t key_sz = 0;
	void *out_buf = params[2].memref.buffer;
	uint32_t out_size = params[2].memref.size;
	const enum processing_func function = PKCS11_FUNCTION_WRAP;

	if (!client || ptypes != exp_pt ||
	    (out_size && !out_buf))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &wrapping_key_handle, sizeof(uint32_t));
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
		goto out_free;
	}

	rc = get_ready_session(session);
	if (rc)
		goto out_free;

	wrapping_key = pkcs11_handle2object(wrapping_key_handle, session);
	if (!wrapping_key) {
		rc = PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID;
		goto out_free;
	}

	key = pkcs11_handle2object(key_handle, session);
	if (!key) {
		rc = PKCS11_CKR_KEY_HANDLE_INVALID;
		goto out_free;
	}

	/*
	 * The wrapping key and key to be wrapped shouldn't be same.
	 * PKCS#11 spec doesn't explicitly state that but logically this isn't
	 * a use case and also acts as an attack vector, so explicitly
	 * disallow this.
	 */
	if (key == wrapping_key) {
		rc = PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID;
		goto out_free;
	}

	rc = set_processing_state(session, function, wrapping_key, NULL);
	if (rc)
		goto out_free;

	/* Check if mechanism can be used for wrapping function */
	rc = check_mechanism_against_processing(session, proc_params->id,
						function,
						PKCS11_FUNC_STEP_INIT);
	if (rc)
		goto out;

	/*
	 * Check if wrapping key has CKA_WRAP set and its key type is
	 * compatible with the mechanism passed
	 */
	rc = check_parent_attrs_against_processing(proc_params->id, function,
						   wrapping_key->attributes);
	if (rc) {
		/*
		 * CKR_KEY_FUNCTION_NOT_PERMITTED is not in the list of errors
		 * specified with C_Wrap() in the specification. So
		 * return the next most appropriate error.
		 */
		if (rc == PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED)
			rc = PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT;

		goto out;
	}

	/* Check access of wrapping key */
	rc = check_access_attrs_against_token(session,
					      wrapping_key->attributes);
	if (rc)
		goto out;

	switch (get_class(key->attributes)) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		break;
	default:
		rc = PKCS11_CKR_KEY_NOT_WRAPPABLE;
		goto out;
	}

	/* Check if key to be wrapped is extractable */
	if (!get_bool(key->attributes, PKCS11_CKA_EXTRACTABLE)) {
		DMSG("Extractable property is false");
		rc = PKCS11_CKR_KEY_UNEXTRACTABLE;
		goto out;
	}

	if (get_bool(key->attributes, PKCS11_CKA_WRAP_WITH_TRUSTED) &&
	    !get_bool(wrapping_key->attributes, PKCS11_CKA_TRUSTED)) {
		DMSG("Wrap with trusted not satisfied");
		rc = PKCS11_CKR_KEY_NOT_WRAPPABLE;
		goto out;
	}

	rc = check_access_attrs_against_token(session, key->attributes);
	if (rc)
		goto out;

	rc = get_attribute_ptr(wrapping_key->attributes,
			       PKCS11_CKA_WRAP_TEMPLATE, &req_attrs, &size);
	if (rc == PKCS11_CKR_OK && size != 0) {
		if (!attributes_match_reference(key->attributes, req_attrs)) {
			rc = PKCS11_CKR_KEY_HANDLE_INVALID;
			goto out;
		}
	}

	rc = alloc_key_data_to_wrap(key->attributes, &key_data, &key_sz);
	if (rc)
		goto out;

	if (processing_is_tee_symm(proc_params->id)) {
		rc = init_symm_operation(session, PKCS11_FUNCTION_ENCRYPT,
					 proc_params, wrapping_key);
		if (rc)
			goto out;

		rc = wrap_data_by_symm_enc(session, key_data, key_sz, out_buf,
					   &out_size);
	} else {
		rc = init_asymm_operation(session, PKCS11_FUNCTION_ENCRYPT,
					  proc_params, wrapping_key);
		if (rc)
			goto out;

		rc = wrap_data_by_asymm_enc(session, key_data, key_sz, out_buf,
					    &out_size);
	}

	if (rc == PKCS11_CKR_OK || rc == PKCS11_CKR_BUFFER_TOO_SMALL)
		params[2].memref.size = out_size;

out:
	release_active_processing(session);
out_free:
	TEE_Free(key_data);
	TEE_Free(proc_params);
	return rc;
}
