/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#include <tee_api_types.h>
#include <tee_api_types_extensions.h>
#include <tee_api.h>
#include <tee_api_extensions.h>
#include <pta_ree_service.h>
#include <string.h>

/*
 * struct __ree_session_handle
 * @handle : maintains the handle of REE service
 * @session: session handle of REE PTA
 */
struct __ree_session_handle {
	uint64_t handle;
	TEE_TASessionHandle session;
};

/**
 * TEE_OpenREESession() - open the REE session
 * The API finds the REE service (either Message Queue or Dynamic Library
 * based) based on the @destination UUID. There are 2 commands issued to
 * tee-supplicant.
 *
 * o One is via TEE_OpenTASession(), where tee-supplicant establish
 *   communication channel with the REE service
 *
 * o Second is via TEE_InvokeTACommand(), where tee-supplicant uses the
 *   established communication mechanism to inform REE service that TA
 *   is from now will be requesting its service. REE service in response
 *   to that can initialize itself for handling the requests.
 */
TEE_Result TEE_OpenREESession(TEE_UUID *destination,
			uint32_t cancellationRequestTimeout,
			uint32_t paramTypes,
			TEE_Param params[TEE_NUM_PARAMS],
			ree_session_handle *ree_session,
			uint32_t *returnOrigin)
{
	ree_session_handle rsess;
	TEE_Param *pparams;
	TEE_Param iparam = {0};
	TEE_UUID ree_pta = PTA_REE_SERVICE_UUID;
	TEE_Result result = TEE_SUCCESS;
	TEE_Param uuid_params[TEE_NUM_PARAMS];
	uint32_t uuid_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (!destination || !ree_session || !returnOrigin)
		return TEE_ERROR_BAD_PARAMETERS;

	rsess = TEE_Malloc(sizeof(*rsess), TEE_MALLOC_FILL_ZERO);
	if (!rsess)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Open a session on the REE PTA */
	result = TEE_OpenTASession(&ree_pta, 0, 0, NULL, &rsess->session, NULL);
	if (result != TEE_SUCCESS) {
		MSG("Failed to open session on REE\n");
		goto err;
	}

	/* Find the REE service identified by "destination" UUID */
	memset(uuid_params, 0, sizeof(uuid_params));
	uuid_params[0].memref.buffer = destination;
	uuid_params[0].memref.size = sizeof(TEE_UUID);
	result = TEE_InvokeTACommand(rsess->session, 0,
				OPTEE_MRC_REE_SERVICE_OPEN, uuid_param_types,
				uuid_params, returnOrigin);
	if (result != TEE_SUCCESS) {
		MSG("Failed to find the ree service\n");
		goto err;
	}
	rsess->handle = uuid_params[1].value.a;

	/*
	 * The API allows NULL params to be sent in OpenSession, however, it is
	 * mandatory to send non-NULL params in the TEE_InvokeTACommand, so,
	 * sending a zero'ed out params in case caller sends in NULL parameter
	 */
	if (params)
		pparams = params;
	else
		pparams = &iparam;

	pparams->value.a = rsess->handle;
	paramTypes = (paramTypes & ~0xF) | TEE_PARAM_TYPE_VALUE_INPUT;
	result = TEE_InvokeTACommand(rsess->session, cancellationRequestTimeout,
				OPTEE_MRC_REE_SERVICE_START, paramTypes,
				pparams, returnOrigin);
	if (result != TEE_SUCCESS) {
		DMSG("Failed to initialize REE service\n");
		goto err;
	}

	*ree_session = rsess;

	return TEE_SUCCESS;

err:
	if (rsess) {
		TEE_CloseTASession(rsess->session);
		TEE_Free(rsess);
	}
	return result;
}

/**
 * TEE_CloseREESession() - close the session on REE service
 */
void TEE_CloseREESession(ree_session_handle ree_session)
{
	TEE_Result result;
	TEE_Param param;
	uint32_t paramTypes = TEE_PARAM_TYPE_VALUE_INPUT;

	/* Inform the REE service, that TA is wants to close its instance */
	param.value.a = ree_session->handle;
	result = TEE_InvokeTACommand(ree_session->session, 0,
				OPTEE_MRC_REE_SERVICE_STOP, paramTypes,
				&param, NULL);
	if (result != TEE_SUCCESS)
		MSG("Failed to close the REE service\n");

	/*
	 * Inform the tee-supplicant to close the communication
	 * channel with REE service
	 */
	param.value.a = ree_session->handle;
	result = TEE_InvokeTACommand(ree_session->session, 0,
				OPTEE_MRC_REE_SERVICE_CLOSE, paramTypes,
				&param, NULL);
	if (result != TEE_SUCCESS)
		MSG("Failed to close the session\n");

	/* Close the session on REE PTA */
	TEE_CloseTASession(ree_session->session);
}

/**
 * TEE_InvokeREECommand() - invoke custom REE command
 */
TEE_Result TEE_InvokeREECommand(ree_session_handle ree_session,
		uint32_t cancellationRequestTimeout,
		uint32_t commandID, uint32_t paramTypes,
		TEE_Param params[TEE_NUM_PARAMS],
		uint32_t *returnOrigin)
{
	TEE_Param *pParam;
	TEE_Param iparam;

	/* The first parameter is reserved for internal usage */
	if (params)
		pParam = &params[0];
	else
		pParam = &iparam;

	/* Override the first param with REE handle information */
	pParam->value.a = ree_session->handle;
	paramTypes = (paramTypes & ~0xF) | TEE_PARAM_TYPE_VALUE_INPUT;

	return TEE_InvokeTACommand(ree_session->session,
				cancellationRequestTimeout,
				commandID, paramTypes,
				pParam, returnOrigin);
}
