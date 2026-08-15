// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_auth.h>
#include <auth/pas_meta.h>
#include <auth/pas_fuse.h>
#include <pta_qcom_pas.h>
#include <ta_qcom_pas.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <types_ext.h>
#include <utee_defines.h>

static size_t session_refcount;
static TEE_TASessionHandle pta_session;

static TEE_Result qcom_pas_init_image(struct qcom_pas_session *s, uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_QCOM_PAS_INIT_IMAGE, pt, params, NULL);
	if (res)
		return res;

	res = pas_auth_save_metadata(s, pt, params);
	if (res)
		return res;

	return pas_auth_prepare_and_authenticate(s, params[0].value.a);
}

static TEE_Result qcom_pas_auth_and_reset(struct qcom_pas_session *s,
					  uint32_t pt,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_auth_verify(s, pta_session, params[0].value.a, params);
	if (res)
		return res;

	return TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				   PTA_QCOM_PAS_AUTH_AND_RESET,
				   pt, params, NULL);
}

static TEE_Result qcom_pas_shutdown(struct qcom_pas_session *s, uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_QCOM_PAS_SHUTDOWN, pt, params, NULL);

	pas_auth_release_metadata(s, params[0].value.a);

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS],
				    void **sess_ctx)
{
	static const TEE_UUID uuid = PTA_QCOM_PAS_UUID;
	TEE_PropSetHandle h = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct qcom_pas_session *s = NULL;
	TEE_Identity id = { };

	res = TEE_AllocatePropertyEnumerator(&h);
	if (res)
		goto out;

	TEE_StartPropertyEnumerator(h, TEE_PROPSET_CURRENT_CLIENT);

	res = TEE_GetPropertyAsIdentity(h, NULL, &id);
	if (res)
		goto out;

	if (id.login != TEE_LOGIN_REE_KERNEL) {
		res = TEE_ERROR_ACCESS_DENIED;
		goto out;
	}

	s = TEE_Malloc(sizeof(*s), TEE_MALLOC_FILL_ZERO);
	if (!s) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (!session_refcount) {
		res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, pt, params,
					&pta_session, NULL);
		if (res) {
			TEE_Free(s);
			goto out;
		}

		res = pas_fuse_open();
		if (res) {
			TEE_CloseTASession(pta_session);
			TEE_Free(s);
			goto out;
		}
	}

	session_refcount++;
	*sess_ctx = s;

out:
	if (h)
		TEE_FreePropertyEnumerator(h);

	return res;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct qcom_pas_session *s = sess_ctx;

	if (s) {
		size_t i = 0;

		for (i = 0; i < PAS_MD_SLOTS; i++)
			TEE_Free(s->slots[i].meta_data);
		TEE_Free(s);
	}

	session_refcount--;

	if (!session_refcount) {
		pas_fuse_close();
		TEE_CloseTASession(pta_session);
	}
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	struct qcom_pas_session *s = sess_ctx;

	switch (cmd_id) {
	case TA_QCOM_PAS_IS_SUPPORTED:
		return TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					   PTA_QCOM_PAS_IS_SUPPORTED,
					   pt, params, NULL);
	case TA_QCOM_PAS_CAPABILITIES:
		return TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					   PTA_QCOM_PAS_CAPABILITIES,
					   pt, params, NULL);
	case TA_QCOM_PAS_INIT_IMAGE:
		return qcom_pas_init_image(s, pt, params);
	case TA_QCOM_PAS_MEM_SETUP:
		return TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					   PTA_QCOM_PAS_MEM_SETUP,
					   pt, params, NULL);
	case TA_QCOM_PAS_GET_RESOURCE_TABLE:
		return TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					   PTA_QCOM_PAS_GET_RESOURCE_TABLE,
					   pt, params, NULL);
	case TA_QCOM_PAS_AUTH_AND_RESET:
		return qcom_pas_auth_and_reset(s, pt, params);
	case TA_QCOM_PAS_SET_REMOTE_STATE:
		return TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					   PTA_QCOM_PAS_SET_REMOTE_STATE,
					   pt, params, NULL);
	case TA_QCOM_PAS_SHUTDOWN:
		return qcom_pas_shutdown(s, pt, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
