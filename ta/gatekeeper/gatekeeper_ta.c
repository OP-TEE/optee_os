// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2017, GlobalLogic  */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "failure_record.h"
#include "gatekeeper_ipc.h"
#include "ta_gatekeeper.h"

static const uint8_t secret_id[] = { 0xB1, 0x6B, 0x00, 0xB5 };

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle secret_obj = TEE_HANDLE_NULL;
	uint8_t secret_data[TEE_SHA256_HASH_SIZE];

	DMSG("Checking master key secret");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, secret_id,
				       sizeof(secret_id),
				       TEE_DATA_FLAG_ACCESS_READ,
				       &secret_obj);

	if (!res) {
		DMSG("Secret is already created");
		goto exit;
	}

	if (res != TEE_ERROR_ITEM_NOT_FOUND) {
		EMSG("Failed to open secret, error=%X", res);
		return res;
	}

	TEE_GenerateRandom(secret_data, sizeof(secret_data));

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
			secret_id,
			sizeof(secret_id),
			TEE_DATA_FLAG_ACCESS_WRITE,
			TEE_HANDLE_NULL, NULL, 0,
			&secret_obj);
	if (res) {
		EMSG("Failed to create secret");
		return res;
	}

	res = TEE_WriteObjectData(secret_obj, (void *)secret_data,
			sizeof(secret_data));
	if (res)
		EMSG("Failed to write secret data");

exit:
	if (secret_obj != TEE_HANDLE_NULL)
		TEE_CloseObject(secret_obj);

	return res;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **sess_ctx __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	init_failure_record();

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
}

static TEE_Result TA_GetMasterKey(TEE_ObjectHandle master_key)
{
	TEE_Result res;
	TEE_Attribute attr;
	uint8_t	secret_data[TEE_SHA256_HASH_SIZE];
	TEE_ObjectHandle secret_obj = TEE_HANDLE_NULL;
	uint32_t read_size = 0;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, secret_id,
				       sizeof(secret_id),
				       TEE_DATA_FLAG_ACCESS_READ,
				       &secret_obj);
	if (res) {
		EMSG("Failed to open secret, error=%X", res);
		goto exit;
	}

	res = TEE_ReadObjectData(secret_obj, secret_data, sizeof(secret_data),
				 &read_size);
	if (res || sizeof(secret_data) != read_size) {
		EMSG("Failed to read secret data, bytes = %u", read_size);
		goto close_obj;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, secret_data,
			     sizeof(secret_data));

	res = TEE_PopulateTransientObject(master_key, &attr, 1);
	if (res)
		EMSG("Failed to set master key attributes");

close_obj:
	TEE_CloseObject(secret_obj);
exit:
	return res;
}

static TEE_Result TA_ComputeSignature(uint8_t *signature,
				      size_t signature_length,
				      TEE_ObjectHandle key,
				      const uint8_t *message,
				      size_t length)
{
	uint32_t buf_length = TEE_SHA256_HASH_SIZE;
	uint8_t buf[buf_length];
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	uint32_t to_write;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
				    TEE_SHA256_HASH_SIZE * 8);
	if (res) {
		EMSG("Failed to allocate HMAC operation");
		goto exit;
	}

	res = TEE_SetOperationKey(op, key);
	if (res) {
		EMSG("Failed to set secret key");
		goto free_op;
	}

	TEE_MACInit(op, NULL, 0);

	TEE_MACComputeFinal(op, (void *)message, length, buf, &buf_length);
	if (res) {
		EMSG("Failed to compute HMAC");
		goto free_op;
	}

	to_write = buf_length;

	if (buf_length > signature_length)
		to_write = signature_length;

	memset(signature, 0, signature_length);
	memcpy(signature, buf, to_write);

free_op:
	TEE_FreeOperation(op);
exit:
	return res;
}

static TEE_Result TA_ComputePasswordSignature(uint8_t *signature,
					      size_t signature_length,
					      TEE_ObjectHandle key,
					      const uint8_t *password,
					      size_t password_length,
					      salt_t salt)
{
	uint8_t *salted_password = NULL;
	TEE_Result res = TEE_SUCCESS;

	salted_password = TEE_Malloc(password_length + sizeof(salt),
				     TEE_MALLOC_FILL_ZERO);
	if (!salted_password)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(salted_password, &salt, sizeof(salt));
	memcpy(salted_password + sizeof(salt), password, password_length);

	res = TA_ComputeSignature(signature, signature_length,
				  key, salted_password,
				  sizeof(salted_password));

	TEE_Free(salted_password);

	return res;
}

static TEE_Result TA_CreatePasswordHandle(struct password_handle
					  *pass_handle,
					  salt_t salt, secure_id_t user_id,
					  uint64_t flags,
					  uint64_t handle_version,
					  const uint8_t *password,
					  uint32_t password_length)
{
	struct password_handle pw_handle;
	const uint32_t metadata_length = sizeof(pw_handle.user_id) +
					 sizeof(pw_handle.flags) +
					 sizeof(pw_handle.version);
	uint8_t *to_sign = NULL;

	TEE_ObjectHandle master_key = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	to_sign = TEE_Malloc(password_length + metadata_length,
			 TEE_MALLOC_FILL_ZERO);
	if (!to_sign) {
		EMSG("Failed to allocate buffer for source data to sign");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
					  TEE_SHA256_HASH_SIZE * 8,
					  &master_key);
	if (res) {
		EMSG("Failed to allocate password key");
		goto free_sign;
	}

	pw_handle.version = handle_version;
	pw_handle.salt = salt;
	pw_handle.user_id = user_id;
	pw_handle.flags = flags;
	pw_handle.hardware_backed = true;

	memcpy(to_sign, &pw_handle, metadata_length);
	memcpy(to_sign + metadata_length, password, password_length);

	res = TA_GetMasterKey(master_key);
	if (res) {
		EMSG("Failed to get master key");
		goto free_key;
	}

	res = TA_ComputePasswordSignature(pw_handle.signature,
					  sizeof(pw_handle.signature),
					  master_key, to_sign,
					  sizeof(to_sign), salt);
	if (res) {
		EMSG("Failed to compute password signature");
		goto free_key;
	}

	memcpy(pass_handle, &pw_handle, sizeof(pw_handle));

free_key:
	TEE_FreeTransientObject(master_key);
free_sign:
	TEE_Free(to_sign);
exit:
	return res;
}

static TEE_Result TA_GetAuthTokenKey(TEE_ObjectHandle key)
{
	TEE_Result res;
	TEE_Param params[TEE_NUM_PARAMS];
	TEE_TASessionHandle sess;
	TEE_Attribute attr;
	const TEE_UUID uuid = TA_KEYMASTER_UUID;

	uint32_t param_types;
	uint32_t return_origin;

	uint8_t	dummy[TEE_SHA256_HASH_SIZE];
	uint8_t	auth_token_key_data[TEE_SHA256_HASH_SIZE];


	DMSG("Connect to keymaster");

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

	res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE,
				param_types, params, &sess,
				&return_origin);
	if (res) {
		EMSG("Failed to connect to keymaster");
		goto exit;
	}

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_MEMREF_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE);
	memset(&params, 0, sizeof(params));

	params[0].memref.buffer = dummy;
	params[0].memref.size = sizeof(dummy);

	params[1].memref.buffer = auth_token_key_data;
	params[1].memref.size = sizeof(auth_token_key_data);

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  KM_GET_AUTHTOKEN_KEY,
				  param_types, params, &return_origin);
	if (res) {
		EMSG("Failed to get authentication token key from Keymaster");
		goto close_sess;
	}

	if (params[1].memref.size != sizeof(auth_token_key_data)) {
		EMSG("Wrong auth_token key size");
		res = TEE_ERROR_CORRUPT_OBJECT;

		goto close_sess;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     auth_token_key_data, sizeof(auth_token_key_data));

	res = TEE_PopulateTransientObject(key, &attr, 1);
	if (res)
		EMSG("Failed to set auth_token key attributes");

close_sess:
	TEE_CloseTASession(sess);
exit:
	return res;
}

static void TA_MintAuthToken(struct hw_auth_token *auth_token,
			     int64_t timestamp,
			     secure_id_t user_id,
			     secure_id_t authenticator_id,
			     uint64_t challenge)
{
	TEE_Result res;

	struct hw_auth_token token;
	TEE_ObjectHandle auth_token_key = TEE_HANDLE_NULL;

	const uint8_t *to_sign = (const uint8_t *)&token;
	const uint32_t to_sign_sz = sizeof(token) - sizeof(token.hmac);

	token.version = HW_AUTH_TOKEN_VERSION;
	token.challenge = challenge;
	token.user_id = user_id;
	token.authenticator_id = authenticator_id;
	token.authenticator_type = TEE_U32_TO_BIG_ENDIAN((uint32_t)
							 HW_AUTH_PASSWORD);
	token.timestamp =  TEE_U64_TO_BIG_ENDIAN(timestamp);
	memset(token.hmac, 0, sizeof(token.hmac));

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
					  TEE_SHA256_HASH_SIZE * 8,
					  &auth_token_key);
	if (res) {
		EMSG("Failed to allocate auth_token key");
		goto exit;
	}

	res = TA_GetAuthTokenKey(auth_token_key);
	if (res) {
		EMSG("Failed to get auth_token key from keymaster");
		goto free_key;
	}

	res = TA_ComputeSignature(token.hmac, sizeof(token.hmac),
				  auth_token_key, to_sign, to_sign_sz);
	if (res) {
		EMSG("Failed to compute auth_token signature");
		memset(token.hmac, 0, sizeof(token.hmac));
		goto free_key;
	}

free_key:
	TEE_FreeTransientObject(auth_token_key);
exit:
	memcpy(auth_token, &token, sizeof(token));
}

static TEE_Result TA_DoVerify(const struct password_handle *expected_handle,
			      const uint8_t *password,
			      uint32_t password_length)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	struct password_handle password_handle;

	if (!password_length || !expected_handle)
		goto exit;

	res = TA_CreatePasswordHandle(&password_handle, expected_handle->salt,
				      expected_handle->user_id,
				      expected_handle->flags,
				      expected_handle->version,
				      password, password_length);
	if (res) {
		EMSG("Failed to create password handle");
		goto exit;
	}

	if (memcmp(password_handle.signature, expected_handle->signature,
		   sizeof(expected_handle->signature)) == 0)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_SIGNATURE_INVALID;

exit:
	return res;
}

static TEE_Result TA_Enroll(TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	/*
	 * Enroll request layout
	 * +--------------------------------+---------------------------------+
	 * | Name                           | Number of bytes                 |
	 * +--------------------------------+---------------------------------+
	 * | uid                            | 4                               |
	 * | desired_password_length        | 4                               |
	 * | desired_password               | #desired_password_length        |
	 * | current_password_length        | 4                               |
	 * | current_password               | #current_password_length        |
	 * | current_password_handle_length | 4                               |
	 * | current_password_handle        | #current_password_handle_length |
	 * +--------------------------------+---------------------------------+
	 */
	uint32_t uid;
	uint32_t desired_password_length;
	const uint8_t *desired_password;
	uint32_t current_password_length;
	const uint8_t *current_password;
	uint32_t current_password_handle_length;
	const uint8_t *current_password_handle;

	const uint8_t *request = (const uint8_t *)params[0].memref.buffer;
	const uint8_t *i_req = request;
	struct failure_record record;

	/*
	 * Enroll response layout
	 * +--------------------------------+---------------------------------+
	 * | Name                           | Number of bytes                 |
	 * +--------------------------------+---------------------------------+
	 * | error                          | 4                               |
	 * +--------------------------------+---------------------------------+
	 * | timeout                        | 4                               |
	 * +------------------------------ OR --------------------------------+
	 * | password_handle_length         | 4                               |
	 * | password_handle                | #password_handle_length         |
	 * +--------------------------------+---------------------------------+
	 */
	uint32_t error = GK_ERROR_NONE;
	uint32_t timeout = 0;
	struct password_handle password_handle;

	uint8_t *response = params[1].memref.buffer;
	uint8_t *i_resp = response;

	const uint32_t max_response_size = sizeof(uint32_t) +
		sizeof(uint32_t) +
		sizeof(struct password_handle);

	secure_id_t user_id = 0;
	uint64_t flags = 0;
	salt_t salt;

	deserialize_int(&i_req, &uid);
	deserialize_blob(&i_req, &desired_password, &desired_password_length);
	deserialize_blob(&i_req, &current_password, &current_password_length);
	deserialize_blob(&i_req, &current_password_handle,
			&current_password_handle_length);

	/* Check request buffer size */
	if (get_size(request, i_req) > params[0].memref.size) {
		EMSG("Wrong request buffer size");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Check response buffer size */
	if (max_response_size > params[1].memref.size) {
		EMSG("Wrong response buffer size");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Check password handle length */
	if (current_password_handle_length != 0 &&
	    current_password_handle_length != sizeof(struct password_handle)) {
		EMSG("Wrong password handle size");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (!current_password_handle_length) {
		/*
		 * Password handle does not match what is stored, generate new
		 * secure user_id
		 */
		TEE_GenerateRandom(&user_id, sizeof(user_id));
	} else {
		uint64_t timestamp;
		bool throttle;

		struct password_handle *pw_handle = (struct password_handle *)
						    current_password_handle;

		if (pw_handle->version > HANDLE_VERSION) {
			EMSG("Wrong handle version %u, required version is %u",
			     pw_handle->version, HANDLE_VERSION);
			error = GK_ERROR_INVALID;
			goto serialize_response;
		}

		user_id = pw_handle->user_id;
		timestamp = get_timestamp();

		throttle = (pw_handle->version >= HANDLE_VERSION_THROTTLE);
		if (throttle) {
			flags |= HANDLE_FLAG_THROTTLE_SECURE;
			get_failure_record(user_id, &record);

			if (throttle_request(&record, timestamp, &timeout)) {
				error = GK_ERROR_RETRY;
				goto serialize_response;
			}

			inc_failure_record(&record, timestamp);
		}

		res = TA_DoVerify(pw_handle, current_password,
				  current_password_length);
		switch (res) {
		case TEE_SUCCESS:
			break;
		case TEE_ERROR_SIGNATURE_INVALID:
			if (throttle && timeout > 0)
				error = GK_ERROR_RETRY;
			else
				error = GK_ERROR_INVALID;

			goto serialize_response;
		default:
			EMSG("Failed to verify password handle");
			goto exit;
		}
	}

	clear_failure_record(user_id);

	TEE_GenerateRandom(&salt, sizeof(salt));
	res = TA_CreatePasswordHandle(&password_handle, salt, user_id, flags,
				      HANDLE_VERSION, desired_password,
				      desired_password_length);
	if (res) {
		EMSG("Failed to create password handle");
		goto exit;
	}

serialize_response:
	serialize_int(&i_resp, error);

	switch (error) {
	case GK_ERROR_INVALID:
	case GK_ERROR_UNKNOWN:
		break;
	case GK_ERROR_RETRY:
		serialize_int(&i_resp, timeout);
		break;
	case GK_ERROR_NONE:
		serialize_blob(&i_resp, (const uint8_t *)&password_handle,
				sizeof(password_handle));
		break;
	default:
		EMSG("Unknown error message!");
		res = TEE_ERROR_GENERIC;
	}

	params[1].memref.size = get_size(response, i_resp);
exit:
	DMSG("Enroll returns 0x%08X, error = %d", res, error);

	return res;
}

static TEE_Result TA_Verify(TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	/*
	 * Verify request layout
	 * +---------------------------------+-------------------- +
	 * | Name                            | Number of bytes     |
	 * +---------------------------------+---------------------+
	 * | uid                             | 4                   |
	 * | challenge                       | 8                   |
	 * | enrolled_password_handle_length | 4                   |
	 * | enrolled_password_handle        | -                   |
	 * | provided_password_length        | 4                   |
	 * | provided_password               | -                   |
	 * +---------------------------------+---------------------+
	 */
	uint32_t uid;
	uint64_t challenge;
	uint32_t enrolled_password_handle_length;
	const uint8_t *enrolled_password_handle;
	uint32_t provided_password_length;
	const uint8_t *provided_password;
	struct failure_record record;

	const uint8_t *request = (const uint8_t *)params[0].memref.buffer;
	const uint8_t *i_req = request;

	/*
	 * Verify response layout
	 * +--------------------------------+---------------------------+
	 * | Name                           | Number of bytes           |
	 * +--------------------------------+---------------------------+
	 * | error                          | 4                         |
	 * +--------------------------------+---------------------------+
	 * | retry_timeout                  | 4                         |
	 * +------------------------------ OR --------------------------+
	 * | response_auth_token_length     | 4                         |
	 * | response_auth_token            | #response_handle_length   |
	 * | response_request_reenroll      | 4                         |
	 * +--------------------------------+---------------------------+
	 */
	uint32_t error = GK_ERROR_NONE;
	uint32_t timeout = 0;
	struct hw_auth_token auth_token;
	bool request_reenroll = false;

	uint8_t *response = params[1].memref.buffer;
	uint8_t *i_resp = response;

	const uint32_t max_response_size = sizeof(uint32_t) +
					   sizeof(uint32_t) +
					   sizeof(struct password_handle) +
					   sizeof(uint32_t);
	struct password_handle *password_handle;
	secure_id_t user_id;
	secure_id_t authenticator_id = 0;

	uint64_t timestamp;
	bool throttle;

	timestamp = get_timestamp();

	deserialize_int(&i_req, &uid);
	deserialize_int64(&i_req, &challenge);
	deserialize_blob(&i_req, &enrolled_password_handle,
			&enrolled_password_handle_length);
	deserialize_blob(&i_req, &provided_password,
			&provided_password_length);

	/* Check request buffer size */
	if (get_size(request, i_req) > params[0].memref.size) {
		EMSG("Wrong request buffer size");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Check response buffer size */
	if (max_response_size > params[1].memref.size) {
		EMSG("Wrong response buffer size");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Check password handle length */
	if (enrolled_password_handle_length == 0 ||
	    enrolled_password_handle_length !=
	    sizeof(struct password_handle)) {
		EMSG("Wrong password handle size");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	password_handle = (struct password_handle *)enrolled_password_handle;

	if (password_handle->version > HANDLE_VERSION) {
		EMSG("Wrong handle version %u, required version is %u",
				password_handle->version, HANDLE_VERSION);
		error = GK_ERROR_INVALID;
		goto serialize_response;
	}

	user_id = password_handle->user_id;

	throttle = (password_handle->version >= HANDLE_VERSION_THROTTLE);
	if (throttle) {
		get_failure_record(user_id, &record);

		if (throttle_request(&record, timestamp, &timeout)) {
			error = GK_ERROR_RETRY;
			goto serialize_response;
		}

		inc_failure_record(&record, timestamp);
	} else {
		request_reenroll = true;
	}

	res = TA_DoVerify(password_handle, provided_password,
			  provided_password_length);
	switch (res) {
	case TEE_SUCCESS:
		TA_MintAuthToken(&auth_token, timestamp, user_id,
				 authenticator_id, challenge);
		if (throttle)
			clear_failure_record(user_id);

		goto serialize_response;
	case TEE_ERROR_SIGNATURE_INVALID:
		if (throttle && timeout > 0)
			error = GK_ERROR_RETRY;
		else
			error = GK_ERROR_INVALID;

		goto serialize_response;
	default:
		EMSG("Failed to verify password handle");
		goto exit;
	}

serialize_response:
	serialize_int(&i_resp, error);

	switch (error) {
	case GK_ERROR_INVALID:
	case GK_ERROR_UNKNOWN:
		break;
	case GK_ERROR_RETRY:
		serialize_int(&i_resp, timeout);
		break;
	case GK_ERROR_NONE:
		serialize_blob(&i_resp, (uint8_t *)&auth_token,
			       sizeof(auth_token));
		serialize_int(&i_resp, (uint32_t) request_reenroll);
		break;
	default:
		EMSG("Unknown error message!");
		res = TEE_ERROR_GENERIC;
	}

	params[1].memref.size = get_size(response, i_resp);
exit:
	DMSG("Verify returns 0x%08X, error = %d", res, error);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE) != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Gatekeeper TA invoke command cmd_id %u", cmd_id);

	switch (cmd_id) {
	case GK_ENROLL:
		return TA_Enroll(params);
	case GK_VERIFY:
		return TA_Verify(params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}
